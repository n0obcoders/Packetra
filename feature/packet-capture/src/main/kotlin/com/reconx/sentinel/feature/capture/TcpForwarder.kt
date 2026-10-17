package com.reconx.sentinel.feature.capture

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * Best-effort userspace TCP relay (a minimal tun2socks). For each TCP flow from
 * the device it terminates the connection locally, opens a protected socket to
 * the real destination, and bridges bytes both ways while maintaining the
 * sequence/ack bookkeeping the device's stack expects. This keeps the device
 * online during capture without native code.
 *
 * HONEST SCOPE: this implements the common connection path (handshake, data,
 * orderly close). It is not a full RFC 793 stack — it does not do selective
 * retransmission, window scaling or out-of-order reassembly — and it must be
 * validated on a device. Capture/analysis/PCAP do not depend on it: they record
 * what the TUN delivers regardless of whether a flow is forwarded.
 */
class TcpForwarder(
    private val tun: TunWriter,
    private val protect: SocketProtector,
    private val onFlow: (ConnKey, Int, Boolean) -> Unit,
    // L7 payload hook (buffer, offset, length, outbound) for DPI / content sniff.
    private val onPayload: (ConnKey, ByteArray, Int, Int, Boolean) -> Unit = { _, _, _, _, _ -> },
    // Optional upstream proxy for captured TCP flows (SOCKS5 / HTTP CONNECT).
    private val proxy: () -> ProxyConfig = { ProxyConfig() },
) {
    private val conns = ConcurrentHashMap<String, Conn>()

    private inner class Conn(val ip: IpPacket.V4, val sport: Int, val dport: Int, val key: ConnKey) {
        val src = ip.src; val dst = ip.dst
        var mySeq = Random.nextLong(0, 0xFFFFFFFFL)
        var myAck = 0L
        @Volatile var socket: Socket? = null
        @Volatile var closed = false
        // Outbound device→remote payloads are handed to a per-connection writer
        // thread via this bounded queue, so the single capture read loop never
        // blocks on a slow/backpressured proxy or remote socket. An empty array is
        // the "shutdown output after draining" sentinel. Capacity bounds memory; if
        // it fills, the segment is simply not ACKed and the device retransmits.
        val outQueue = ArrayBlockingQueue<ByteArray>(OUT_QUEUE_CAP)
    }

    private val FIN = 0x01; private val SYN = 0x02; private val RST = 0x04
    private val PSH = 0x08; private val ACK = 0x10

    fun handle(ip: IpPacket.V4, buf: ByteArray, len: Int) {
        val l4 = ip.l4Off
        val sport = IpPacket.u16(buf, l4); val dport = IpPacket.u16(buf, l4 + 2)
        val seq = IpPacket.u32(buf, l4 + 4); val ack = IpPacket.u32(buf, l4 + 8)
        val dataOff = ((buf[l4 + 12].toInt() ushr 4) and 0xF) * 4
        val flags = buf[l4 + 13].toInt() and 0xFF
        val payloadOff = l4 + dataOff
        val payloadLen = (ip.totalLen - (ip.ihl) - dataOff).coerceIn(0, len - payloadOff)
        val k = ConnKey("TCP", IpPacket.ipToString(ip.src), sport, IpPacket.ipToString(ip.dst), dport)
        onFlow(k, payloadLen, true)
        if (payloadLen > 0) runCatching { onPayload(k, buf, payloadOff, payloadLen, true) }

        val mapKey = k.toString()
        if (flags and SYN != 0 && conns[mapKey] == null) {
            val c = Conn(ip, sport, dport, k); c.myAck = (seq + 1) and 0xFFFFFFFFL
            conns[mapKey] = c
            openRemote(c)
            return
        }
        val c = conns[mapKey] ?: return
        if (flags and RST != 0) { teardown(c); return }
        if (payloadLen > 0) {
            // Hand the bytes to the writer thread (never block the read loop here).
            // Only ACK if they were queued; a full queue means genuine backpressure,
            // so we leave the segment unacked and let the device retransmit it.
            if (c.outQueue.offer(buf.copyOfRange(payloadOff, payloadOff + payloadLen))) {
                c.myAck = (c.myAck + payloadLen) and 0xFFFFFFFFL
                sendFlags(c, ACK)
            }
        }
        if (flags and FIN != 0) {
            c.myAck = (c.myAck + 1) and 0xFFFFFFFFL
            c.outQueue.offer(ByteArray(0)) // shut output down once queued data is written
            sendFlags(c, ACK)
            sendFlags(c, FIN or ACK); c.mySeq = (c.mySeq + 1) and 0xFFFFFFFFL
        }
    }

    private fun openRemote(c: Conn) {
        thread(isDaemon = true, name = "tcp-${c.sport}") {
            val cfg = runCatching { proxy() }.getOrDefault(ProxyConfig())
            val s = Socket()
            // When a proxy is configured, connect to the proxy and ask it to reach
            // the real destination; otherwise connect directly. Either way this is
            // plain routing — no payload is decrypted.
            val ok = runCatching {
                protect.protect(s)
                if (cfg.enabled) {
                    s.connect(InetSocketAddress(cfg.host, cfg.port), 8000)
                    ProxyHandshake.connect(cfg, c.dst, c.dport, s.getOutputStream(), s.getInputStream())
                } else {
                    s.connect(InetSocketAddress(InetAddress.getByAddress(c.dst), c.dport), 8000); true
                }
            }.getOrDefault(false)
            if (!ok) { runCatching { s.close() }; sendFlags(c, RST or ACK); conns.remove(c.key.toString()); return@thread }
            c.socket = s
            // SYN-ACK: seq = our ISN, ack = client seq+1
            sendFlags(c, SYN or ACK); c.mySeq = (c.mySeq + 1) and 0xFFFFFFFFL
            // Dedicated outbound writer: drains queued device→remote bytes to the
            // socket, off the capture read loop, so proxy/remote backpressure can
            // never stall capturing other flows.
            val out = runCatching { s.getOutputStream() }.getOrNull()
            if (out != null) thread(isDaemon = true, name = "tcp-out-${c.sport}") {
                while (!c.closed) {
                    val chunk = runCatching { c.outQueue.poll(500, TimeUnit.MILLISECONDS) }.getOrNull() ?: continue
                    if (chunk.isEmpty()) { runCatching { s.shutdownOutput() }; continue }
                    val wrote = runCatching { out.write(chunk); out.flush(); true }.getOrDefault(false)
                    if (!wrote) break
                }
            }
            val input = runCatching { s.getInputStream() }.getOrNull() ?: return@thread
            val buf = ByteArray(16384)
            while (!c.closed) {
                val n = runCatching { input.read(buf) }.getOrDefault(-1)
                if (n <= 0) break
                onFlow(c.key, n, false)
                runCatching { onPayload(c.key, buf, 0, n, false) }
                sendData(c, buf, n)
            }
            // remote closed: FIN to app
            sendFlags(c, FIN or ACK); c.mySeq = (c.mySeq + 1) and 0xFFFFFFFFL
            teardown(c)
        }
    }

    private fun sendData(c: Conn, data: ByteArray, len: Int) {
        val seg = tcpHeader(c, PSH or ACK, len)
        System.arraycopy(data, 0, seg, 20, len)
        tun.write(IpPacket.buildV4(c.dst, c.src, IpPacket.PROTO_TCP, seg))
        c.mySeq = (c.mySeq + len) and 0xFFFFFFFFL
    }

    private fun sendFlags(c: Conn, flags: Int) {
        tun.write(IpPacket.buildV4(c.dst, c.src, IpPacket.PROTO_TCP, tcpHeader(c, flags, 0)))
    }

    private fun tcpHeader(c: Conn, flags: Int, payloadLen: Int): ByteArray {
        val seg = ByteArray(20 + payloadLen)
        put16(seg, 0, c.dport); put16(seg, 2, c.sport)     // reply: remote port -> app port
        put32(seg, 4, c.mySeq); put32(seg, 8, c.myAck)
        seg[12] = (5 shl 4).toByte(); seg[13] = flags.toByte()
        put16(seg, 14, 65535)                               // window
        return seg
    }

    private fun teardown(c: Conn) {
        if (c.closed) return
        c.closed = true
        runCatching { c.socket?.close() }
        conns.remove(c.key.toString())
    }

    /** Tear down a connection the firewall now blocks, so an in-flight flow is
     *  severed (RST on next app packet) rather than left running. */
    fun drop(key: ConnKey) { conns[key.toString()]?.let { teardown(it) } }

    fun closeAll() { conns.values.forEach { teardown(it) } }
    private companion object { const val OUT_QUEUE_CAP = 1024 }
    private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte() }
    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte()
        b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
    }
}

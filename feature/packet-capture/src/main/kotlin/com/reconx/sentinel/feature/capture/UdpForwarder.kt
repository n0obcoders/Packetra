package com.reconx.sentinel.feature.capture

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * Userspace UDP relay so the device keeps UDP connectivity (DNS, QUIC, etc.)
 * while captured. For each outbound 4-tuple it opens one protected DatagramSocket
 * to the real destination, forwards the payload, and a reader thread wraps each
 * reply in a fresh IPv4/UDP packet injected back into the TUN. Stateless per
 * datagram, so this path is straightforward and reliable.
 */
class UdpForwarder(
    private val tun: TunWriter,
    private val protect: DatagramProtector,
    private val onFlow: (ConnKey, Int, Boolean) -> Unit,
    private val onDnsPayload: (ByteArray, Int, Int) -> Unit,
    private val onPayload: (ConnKey, ByteArray, Int, Int, Boolean) -> Unit = { _, _, _, _, _ -> },
) {
    private val sessions = ConcurrentHashMap<String, DatagramSocket>()

    fun handle(ip: IpPacket.V4, buf: ByteArray, len: Int) {
        val l4 = ip.l4Off
        val sport = IpPacket.u16(buf, l4)
        val dport = IpPacket.u16(buf, l4 + 2)
        val payloadOff = l4 + 8
        val payloadLen = (IpPacket.u16(buf, l4 + 4) - 8).coerceIn(0, len - payloadOff)
        val key = ConnKey("UDP", IpPacket.ipToString(ip.src), sport, IpPacket.ipToString(ip.dst), dport)
        onFlow(key, payloadLen, true)
        if (payloadLen > 0) runCatching { onPayload(key, buf, payloadOff, payloadLen, true) }
        if (dport == 53) onDnsPayload(buf, payloadOff, payloadLen)

        val mapKey = key.toString()
        val sock = sessions.getOrPut(mapKey) {
            DatagramSocket().also { s ->
                protect.protect(s)
                thread(isDaemon = true, name = "udp-$sport") { readLoop(s, ip, sport, dport, key) }
            }
        }
        runCatching {
            val data = buf.copyOfRange(payloadOff, payloadOff + payloadLen)
            sock.send(DatagramPacket(data, data.size, InetSocketAddress(InetAddress.getByAddress(ip.dst), dport)))
        }
    }

    private fun readLoop(s: DatagramSocket, ip: IpPacket.V4, sport: Int, dport: Int, key: ConnKey) {
        val buf = ByteArray(32767)
        s.soTimeout = 20000
        while (!s.isClosed) {
            val pkt = DatagramPacket(buf, buf.size)
            val ok = runCatching { s.receive(pkt); true }.getOrDefault(false)
            if (!ok) break
            val data = pkt.data.copyOfRange(0, pkt.length)
            onFlow(key, data.size, false)
            if (data.isNotEmpty()) runCatching { onPayload(key, data, 0, data.size, false) }
            // Build UDP segment: dst/src swapped (reply flows dst->src)
            val udp = ByteArray(8 + data.size)
            put16(udp, 0, dport); put16(udp, 2, sport); put16(udp, 4, 8 + data.size)
            System.arraycopy(data, 0, udp, 8, data.size)
            tun.write(IpPacket.buildV4(ip.dst, ip.src, IpPacket.PROTO_UDP, udp))
        }
        sessions.remove(key.toString()); runCatching { s.close() }
    }

    /** Tear down a session the firewall now blocks, so an in-flight flow (e.g. a
     *  call already running when the rule was applied) stops sending/receiving. */
    fun drop(key: ConnKey) { sessions.remove(key.toString())?.let { runCatching { it.close() } } }

    fun closeAll() { sessions.values.forEach { runCatching { it.close() } }; sessions.clear() }
    private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte() }
}

data class ConnKey(val proto: String, val srcIp: String, val srcPort: Int, val dstIp: String, val dstPort: Int) {
    override fun toString() = "$proto|$srcIp:$srcPort|$dstIp:$dstPort"
}

package com.reconx.sentinel.feature.capture

import java.io.BufferedOutputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * PCAP-over-IP: a small TCP server that streams the live capture as a classic
 * libpcap byte stream. A desktop analyst points Wireshark at "TCP@<device-ip>:
 * <port>" and watches the device's own traffic in real time — no file transfer.
 *
 * Each connected client first receives the pcap global header, then every packet
 * as it is captured. A slow/broken client is dropped without affecting capture.
 * Implements [PacketSink] so it plugs in beside the file writer. Bind host
 * defaults to all interfaces so a LAN desktop can reach it; the operator starts
 * it explicitly (off by default).
 */
class PcapOverIpServer(
    private val port: Int = 9922,
    private val snaplen: Int = 65535,
    private val bindHost: String? = null, // null = all interfaces
) : PacketSink {

    @Volatile override var packets: Long = 0; private set
    @Volatile var clients: Int = 0; private set
    @Volatile private var running = false
    private var server: ServerSocket? = null
    private val sinks = CopyOnWriteArrayList<OutputStream>()
    private var acceptThread: Thread? = null

    fun start() {
        if (running) return
        running = true
        val ss = if (bindHost != null) ServerSocket(port, 4, java.net.InetAddress.getByName(bindHost))
                 else ServerSocket(port)
        server = ss
        acceptThread = Thread {
            while (running) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
                runCatching { onClient(sock) }
            }
        }.apply { isDaemon = true; start() }
    }

    private fun onClient(sock: Socket) {
        val out = BufferedOutputStream(sock.getOutputStream())
        synchronized(out) { writeGlobalHeader(out); out.flush() }
        sinks.add(out); clients = sinks.size
    }

    @Synchronized override fun write(buf: ByteArray, len: Int) {
        if (sinks.isEmpty()) return
        val n = minOf(len, snaplen)
        if (n <= 0) return
        val now = System.currentTimeMillis()
        val dead = ArrayList<OutputStream>()
        for (out in sinks) {
            try {
                synchronized(out) {
                    writeU32(out, now / 1000); writeU32(out, (now % 1000) * 1000)
                    writeU32(out, n.toLong()); writeU32(out, len.toLong())
                    out.write(buf, 0, n); out.flush()
                }
            } catch (t: Throwable) { dead.add(out) }
        }
        if (dead.isNotEmpty()) { sinks.removeAll(dead); clients = sinks.size }
        packets++
    }

    override fun close() {
        running = false
        runCatching { server?.close() }
        sinks.forEach { runCatching { it.close() } }
        sinks.clear(); clients = 0
    }

    private fun writeGlobalHeader(out: OutputStream) {
        writeU32(out, 0xa1b2c3d4); writeU16(out, 2); writeU16(out, 4)
        writeU32(out, 0); writeU32(out, 0); writeU32(out, snaplen.toLong()); writeU32(out, 101)
    }
    private fun writeU32(out: OutputStream, v: Long) {
        out.write((v and 0xFF).toInt()); out.write(((v ushr 8) and 0xFF).toInt())
        out.write(((v ushr 16) and 0xFF).toInt()); out.write(((v ushr 24) and 0xFF).toInt())
    }
    private fun writeU16(out: OutputStream, v: Int) { out.write(v and 0xFF); out.write((v ushr 8) and 0xFF) }
}

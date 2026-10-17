package com.reconx.sentinel.feature.capture

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream

/**
 * Writes a classic libpcap file (magic 0xa1b2c3d4) with link type LINKTYPE_RAW
 * (101) — each record is a raw IPv4/IPv6 packet, exactly what the TUN gives us.
 * The resulting .pcap opens in Wireshark/tcpdump. Thread-safe; bounded snaplen.
 */
class PcapWriter(private val file: File, private val snaplen: Int = 65535) : PacketSink {
    private val out = BufferedOutputStream(FileOutputStream(file))
    @Volatile override var packets: Long = 0; private set

    init {
        // Global header
        writeU32(0xa1b2c3d4)       // magic
        writeU16(2); writeU16(4)   // version 2.4
        writeU32(0)                // thiszone
        writeU32(0)                // sigfigs
        writeU32(snaplen.toLong()) // snaplen
        writeU32(101)              // LINKTYPE_RAW
    }

    @Synchronized override fun write(buf: ByteArray, len: Int) {
        val n = minOf(len, snaplen)
        if (n <= 0) return
        val now = System.currentTimeMillis()
        writeU32(now / 1000)             // ts_sec
        writeU32((now % 1000) * 1000)    // ts_usec
        writeU32(n.toLong())             // incl_len
        writeU32(len.toLong())           // orig_len
        out.write(buf, 0, n)
        packets++
    }

    @Synchronized override fun close() { runCatching { out.flush(); out.close() } }

    private fun writeU32(v: Long) {
        out.write((v and 0xFF).toInt()); out.write(((v ushr 8) and 0xFF).toInt())
        out.write(((v ushr 16) and 0xFF).toInt()); out.write(((v ushr 24) and 0xFF).toInt())
    }
    private fun writeU16(v: Int) { out.write(v and 0xFF); out.write((v ushr 8) and 0xFF) }
}

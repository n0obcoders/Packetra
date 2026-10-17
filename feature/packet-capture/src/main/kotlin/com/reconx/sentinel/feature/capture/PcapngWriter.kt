package com.reconx.sentinel.feature.capture

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream

/**
 * Writes a PCAP Next Generation (.pcapng) capture file — the modern Wireshark
 * format — with a single interface of link type LINKTYPE_RAW (101), matching the
 * raw IPv4/IPv6 packets the TUN delivers. Each packet is stored as an Enhanced
 * Packet Block with a microsecond timestamp. All blocks are little-endian, and
 * every block carries its total length at both ends per the pcapng spec, so the
 * output opens cleanly in Wireshark/tshark. Thread-safe; bounded snaplen.
 *
 * PCAPNG is preferred over classic pcap for deep inspection because it preserves
 * per-packet metadata and is the default Wireshark save format.
 */
class PcapngWriter(private val file: File, private val snaplen: Int = 65535) : PacketSink {
    private val out = BufferedOutputStream(FileOutputStream(file))
    @Volatile override var packets: Long = 0; private set

    init {
        writeSectionHeader()
        writeInterfaceDescription()
    }

    private fun writeSectionHeader() {
        // Section Header Block (SHB), no options.
        u32(0x0A0D0D0A)          // block type
        u32(28)                  // block total length
        u32(0x1A2B3C4D)          // byte-order magic
        u16(1); u16(0)           // version 1.0
        u32(0xFFFFFFFF); u32(0xFFFFFFFF) // section length = -1 (unknown)
        u32(28)                  // block total length (trailer)
    }

    private fun writeInterfaceDescription() {
        // Interface Description Block (IDB), no options.
        u32(0x00000001)          // block type
        u32(20)                  // block total length
        u16(101); u16(0)         // linktype LINKTYPE_RAW, reserved
        u32(snaplen.toLong())    // snaplen
        u32(20)                  // block total length (trailer)
    }

    @Synchronized override fun write(buf: ByteArray, len: Int) {
        val capLen = minOf(len, snaplen).coerceAtLeast(0)
        if (capLen == 0) return
        val pad = (4 - (capLen % 4)) % 4
        val total = 32 + capLen + pad
        val us = System.currentTimeMillis() * 1000L  // microseconds since epoch

        u32(0x00000006)                 // block type: Enhanced Packet Block
        u32(total.toLong())             // block total length
        u32(0)                          // interface id
        u32((us ushr 32) and 0xFFFFFFFF) // timestamp high
        u32(us and 0xFFFFFFFF)          // timestamp low
        u32(capLen.toLong())            // captured length
        u32(len.toLong())               // original length
        out.write(buf, 0, capLen)
        repeat(pad) { out.write(0) }    // pad data to 32-bit boundary
        u32(total.toLong())             // block total length (trailer)
        packets++
    }

    @Synchronized override fun close() { runCatching { out.flush(); out.close() } }

    private fun u32(v: Long) {
        out.write((v and 0xFF).toInt()); out.write(((v ushr 8) and 0xFF).toInt())
        out.write(((v ushr 16) and 0xFF).toInt()); out.write(((v ushr 24) and 0xFF).toInt())
    }
    private fun u32(v: Int) = u32(v.toLong() and 0xFFFFFFFFL)
    private fun u16(v: Int) { out.write(v and 0xFF); out.write((v ushr 8) and 0xFF) }
}

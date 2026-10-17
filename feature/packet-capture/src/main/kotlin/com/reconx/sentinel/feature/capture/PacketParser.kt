package com.reconx.sentinel.feature.capture

/**
 * Minimal, defensive IPv4/IPv6 + TCP/UDP header parser. Returns null on any
 * malformed/short packet rather than throwing (spec §4 "safe handling of
 * malformed packets"). Reads only header fields needed for flow metadata.
 */
object PacketParser {
    data class Parsed(val protocol: String, val sourcePort: Int, val destIp: String, val destPort: Int)

    fun parseOutbound(buf: ByteArray, len: Int): Parsed? {
        if (len < 20) return null
        val version = (buf[0].toInt() ushr 4) and 0xF
        return when (version) {
            4 -> parseV4(buf, len)
            6 -> parseV6(buf, len)
            else -> null
        }
    }

    private fun parseV4(buf: ByteArray, len: Int): Parsed? {
        val ihl = (buf[0].toInt() and 0xF) * 4
        if (ihl < 20 || len < ihl + 4) return null
        val proto = buf[9].toInt() and 0xFF
        val dip = (0..3).joinToString(".") { (buf[16 + it].toInt() and 0xFF).toString() }
        val sport = u16(buf, ihl); val dport = u16(buf, ihl + 2)
        return when (proto) {
            6 -> Parsed("TCP", sport, dip, dport)
            17 -> Parsed("UDP", sport, dip, dport)
            else -> null
        }
    }

    private fun parseV6(buf: ByteArray, len: Int): Parsed? {
        if (len < 48) return null
        val next = buf[6].toInt() and 0xFF
        val dip = (0 until 16 step 2).joinToString(":") {
            String.format("%02x%02x", buf[24 + it].toInt() and 0xFF, buf[25 + it].toInt() and 0xFF)
        }
        val sport = u16(buf, 40); val dport = u16(buf, 42)
        return when (next) {
            6 -> Parsed("TCP", sport, dip, dport)
            17 -> Parsed("UDP", sport, dip, dport)
            else -> null
        }
    }

    private fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
}

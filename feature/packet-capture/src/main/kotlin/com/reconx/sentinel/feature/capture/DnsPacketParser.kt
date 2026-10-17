package com.reconx.sentinel.feature.capture

/**
 * Extracts query names and A/AAAA answers from a DNS message (the UDP/53
 * payload), so captured flows can be annotated with the hostname the device
 * looked up. Defensive: returns empty on any malformed message. Reads names
 * only — no resolution, no payload beyond the DNS message itself.
 */
object DnsPacketParser {
    data class Dns(val queries: List<String>, val answers: Map<String, String>)

    fun parse(buf: ByteArray, off: Int, len: Int): Dns? {
        if (len < 12) return null
        return try {
            val end = off + len
            val qd = IpPacket.u16(buf, off + 4)
            val an = IpPacket.u16(buf, off + 6)
            var p = off + 12
            val queries = mutableListOf<String>()
            repeat(qd) {
                val (name, next) = readName(buf, p, off, end) ?: return null
                queries.add(name)
                p = next + 4 // QTYPE + QCLASS
            }
            val answers = mutableMapOf<String, String>()
            repeat(an) {
                val (name, next) = readName(buf, p, off, end) ?: return@repeat
                if (next + 10 > end) return@repeat
                val type = IpPacket.u16(buf, next)
                val rdlen = IpPacket.u16(buf, next + 8)
                val rdata = next + 10
                if (rdata + rdlen > end) return@repeat
                when (type) {
                    1 -> if (rdlen == 4) answers[IpPacket.ipToString(buf.copyOfRange(rdata, rdata + 4))] = name
                    28 -> if (rdlen == 16) answers[ipv6(buf, rdata)] = name
                }
                p = rdata + rdlen
            }
            Dns(queries, answers)
        } catch (_: Throwable) { null }
    }

    private fun readName(buf: ByteArray, start: Int, msgStart: Int, end: Int): Pair<String, Int>? {
        val sb = StringBuilder(); var p = start; var jumped = false; var after = start; var guard = 0
        while (p < end) {
            if (guard++ > 128) return null
            val l = buf[p].toInt() and 0xFF
            when {
                l == 0 -> { if (!jumped) after = p + 1; return sb.toString().trimEnd('.') to after }
                l and 0xC0 == 0xC0 -> {
                    if (p + 1 >= end) return null
                    if (!jumped) after = p + 2
                    p = msgStart + (((l and 0x3F) shl 8) or (buf[p + 1].toInt() and 0xFF)); jumped = true
                }
                else -> { if (p + 1 + l > end) return null
                    sb.append(String(buf, p + 1, l)).append('.'); p += 1 + l }
            }
        }
        return null
    }

    private fun ipv6(b: ByteArray, o: Int): String =
        (0 until 16 step 2).joinToString(":") { String.format("%02x%02x", b[o + it].toInt() and 0xFF, b[o + it + 1].toInt() and 0xFF) }
}

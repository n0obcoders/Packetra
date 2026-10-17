package com.reconx.sentinel.feature.capture

/**
 * Formats raw bytes into a classic hex dump (offset | hex | ASCII), the same
 * layout tcpdump/wireshark use. Pure and unit-tested. These are packet bytes as
 * seen on the TUN (never decrypted), so a dump of an encrypted payload is just
 * ciphertext — honest about what is and isn't readable.
 */
object HexDump {
    private const val HEX = "0123456789abcdef"

    /** @param width bytes per row (16 is conventional). */
    fun format(bytes: ByteArray, len: Int = bytes.size, width: Int = 16): String {
        val n = len.coerceIn(0, bytes.size)
        if (n == 0) return ""
        val sb = StringBuilder()
        var off = 0
        while (off < n) {
            // offset column, 8 hex digits
            sb.append(hex4(off ushr 16)).append(hex4(off and 0xFFFF)).append("  ")
            val rowEnd = minOf(off + width, n)
            // hex column
            for (i in off until off + width) {
                if (i < rowEnd) {
                    val b = bytes[i].toInt() and 0xFF
                    sb.append(HEX[b ushr 4]).append(HEX[b and 0xF]).append(' ')
                } else sb.append("   ")
                if (i - off == width / 2 - 1) sb.append(' ') // mid-row gap
            }
            sb.append(' ')
            // ASCII column
            for (i in off until rowEnd) {
                val b = bytes[i].toInt() and 0xFF
                sb.append(if (b in 0x20..0x7E) b.toChar() else '.')
            }
            if (rowEnd < n) sb.append('\n')
            off = rowEnd
        }
        return sb.toString()
    }

    private fun hex4(v: Int): String {
        val b = StringBuilder(4)
        b.append(HEX[(v ushr 12) and 0xF]); b.append(HEX[(v ushr 8) and 0xF])
        b.append(HEX[(v ushr 4) and 0xF]); b.append(HEX[v and 0xF])
        return b.toString()
    }
}

package com.reconx.sentinel.feature.capture

/**
 * Extracts the SNI (server_name) hostname from a TLS ClientHello. The SNI is
 * sent in cleartext at the start of every TLS handshake, so this reveals which
 * host an app is connecting to WITHOUT any decryption — purely passive metadata,
 * exactly like Wireshark's "tls.handshake.extensions_server_name".
 *
 * Input is the TCP payload (the bytes after the TCP header). Returns the host or
 * null if the payload is not a ClientHello or has no SNI. Bounds-checked
 * throughout so malformed/truncated records never throw.
 */
object TlsParser {
    fun extractSni(buf: ByteArray, off: Int, len: Int): String? {
        var p = off
        val end = off + len
        fun u8(i: Int) = buf[i].toInt() and 0xFF
        fun u16(i: Int) = (u8(i) shl 8) or u8(i + 1)
        // TLS record: content type 22 (handshake), version, length
        if (end - p < 5) return null
        if (u8(p) != 0x16) return null                 // handshake record
        p += 3                                         // skip type + version(2)
        val recLen = u16(p); p += 2
        if (p + recLen > end) return null
        // Handshake: type 1 (ClientHello), length(3)
        if (p + 4 > end) return null
        if (u8(p) != 0x01) return null                 // ClientHello
        p += 4                                         // type(1) + length(3)
        p += 2                                         // client_version(2)
        p += 32                                        // random(32)
        if (p >= end) return null
        val sidLen = u8(p); p += 1 + sidLen            // session_id
        if (p + 2 > end) return null
        val csLen = u16(p); p += 2 + csLen             // cipher_suites
        if (p + 1 > end) return null
        val compLen = u8(p); p += 1 + compLen          // compression_methods
        if (p + 2 > end) return null
        val extTotal = u16(p); p += 2                  // extensions length
        val extEnd = minOf(p + extTotal, end)
        while (p + 4 <= extEnd) {
            val extType = u16(p); p += 2
            val extLen = u16(p); p += 2
            if (extType == 0x0000) {                   // server_name
                var q = p + 2                          // skip server_name_list length(2)
                if (q + 3 > extEnd) return null
                val nameType = u8(q); q += 1
                val nameLen = u16(q); q += 2
                if (nameType != 0 || q + nameLen > extEnd) return null
                val sb = StringBuilder(nameLen)
                for (i in 0 until nameLen) sb.append((buf[q + i].toInt() and 0xFF).toChar())
                return sb.toString().lowercase().takeIf { it.isNotEmpty() }
            }
            p += extLen
        }
        return null
    }
}

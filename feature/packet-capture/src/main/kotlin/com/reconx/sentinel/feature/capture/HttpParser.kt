package com.reconx.sentinel.feature.capture

/**
 * Extracts metadata from a cleartext HTTP/1.x request at the start of a TCP
 * payload: method, path and the Host header (so the real hostname is recovered
 * even when the connection is to a shared IP). This is passive — it only reads
 * what the app already sends in the clear. HTTPS traffic is encrypted and is NOT
 * parsed here (no decryption); for those the TLS SNI is used instead.
 */
object HttpParser {
    private val METHODS = setOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT")

    data class Req(val method: String, val path: String, val host: String?)

    fun parseRequest(buf: ByteArray, off: Int, len: Int): Req? {
        if (len < 16) return null
        // Read a bounded prefix as ASCII (headers only).
        val max = minOf(len, 2048)
        val text = StringBuilder(max)
        for (i in 0 until max) {
            val c = buf[off + i].toInt() and 0xFF
            if (c == 0) break
            text.append(c.toChar())
        }
        val s = text.toString()
        val firstLineEnd = s.indexOf("\r\n").takeIf { it > 0 } ?: return null
        val requestLine = s.substring(0, firstLineEnd).split(' ')
        if (requestLine.size < 3) return null
        val method = requestLine[0]
        if (method !in METHODS) return null
        if (!requestLine[2].startsWith("HTTP/")) return null
        val host = Regex("(?im)^Host:[ \\t]*([^\\r\\n]+)").find(s)?.groupValues?.get(1)?.trim()?.lowercase()
        return Req(method, requestLine[1], host?.takeIf { it.isNotEmpty() })
    }
}

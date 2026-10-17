package com.reconx.sentinel.feature.capture

/**
 * Best-effort detection of WHAT a flow is carrying — image / video / audio /
 * document / text / archive — from the bytes that are actually readable.
 *
 * HONEST SCOPE: this only ever sees cleartext. A magic-number match works on a
 * plaintext HTTP body (or any non-encrypted stream); an HTTPS/TLS/QUIC payload
 * is ciphertext, so [sniff] returns null for it and the UI shows "encrypted".
 * There is no decryption here — this is the same signature-matching `file(1)`
 * and Wireshark do on the cleartext they can see.
 */
object ContentTypeDetector {

    /** A human-facing classification of carried content. */
    data class Kind(val group: String, val label: String) {
        override fun toString() = label
    }

    /**
     * Sniff a payload by magic bytes. [off]/[len] bound the window to inspect.
     * For a cleartext HTTP response the caller should pass the body offset (after
     * the header block) — but [sniff] also skips a leading HTTP header itself as a
     * convenience. Returns null when nothing recognizable is found (e.g. ciphertext).
     */
    fun sniff(buf: ByteArray, off: Int, len: Int): Kind? {
        if (len <= 0 || off < 0 || off + len > buf.size) return null
        // If this looks like an HTTP response, prefer its declared Content-Type and
        // then sniff the body after the blank line.
        httpContentType(buf, off, len)?.let { return it }
        var p = off
        var n = len
        val bodyStart = httpBodyOffset(buf, off, len)
        if (bodyStart != null) { p = bodyStart; n = len - (bodyStart - off) }
        return sniffMagic(buf, p, n)
    }

    /** Map a MIME type string (e.g. an HTTP Content-Type header) to a Kind. */
    fun fromMime(mime: String?): Kind? {
        if (mime.isNullOrBlank()) return null
        val m = mime.substringBefore(';').trim().lowercase()
        return when {
            m.startsWith("image/") -> Kind("image", "Image (${m.removePrefix("image/").uppercase()})")
            m.startsWith("video/") -> Kind("video", "Video (${m.removePrefix("video/").uppercase()})")
            m.startsWith("audio/") -> Kind("audio", "Audio (${m.removePrefix("audio/").uppercase()})")
            m == "application/pdf" -> Kind("document", "PDF")
            m == "application/json" -> Kind("text", "JSON")
            m == "application/xml" || m == "text/xml" -> Kind("text", "XML")
            m == "text/html" -> Kind("text", "HTML")
            m.startsWith("text/") -> Kind("text", "Text (${m.removePrefix("text/")})")
            m == "application/zip" -> Kind("archive", "ZIP archive")
            m == "application/gzip" || m == "application/x-gzip" -> Kind("archive", "gzip")
            m.startsWith("application/") && m.contains("font") -> Kind("font", "Font")
            m == "application/octet-stream" -> Kind("binary", "Binary")
            m.startsWith("application/") -> Kind("binary", m)
            else -> null
        }
    }

    // ---- magic-number table ----

    private fun sniffMagic(buf: ByteArray, off: Int, len: Int): Kind? {
        if (len <= 0) return null
        fun at(i: Int) = buf[off + i].toInt() and 0xFF
        fun has(vararg sig: Int): Boolean {
            if (len < sig.size) return false
            for (i in sig.indices) if (sig[i] >= 0 && at(i) != sig[i]) return false
            return true
        }
        return when {
            has(0xFF, 0xD8, 0xFF) -> Kind("image", "Image (JPEG)")
            has(0x89, 0x50, 0x4E, 0x47) -> Kind("image", "Image (PNG)")
            has(0x47, 0x49, 0x46, 0x38) -> Kind("image", "Image (GIF)")
            has(0x42, 0x4D) -> Kind("image", "Image (BMP)")
            len >= 12 && has(0x52, 0x49, 0x46, 0x46) && at(8) == 0x57 && at(9) == 0x45 &&
                at(10) == 0x42 && at(11) == 0x50 -> Kind("image", "Image (WebP)")
            len >= 12 && at(0) == 0x00 && at(1) == 0x00 && at(2) == 0x00 &&
                at(4) == 0x66 && at(5) == 0x74 && at(6) == 0x79 && at(7) == 0x70 ->
                Kind("video", "Video (MP4/ISO-BMFF)")
            has(0x1A, 0x45, 0xDF, 0xA3) -> Kind("video", "Video (Matroska/WebM)")
            has(0x46, 0x4C, 0x56) -> Kind("video", "Video (FLV)")
            has(0x25, 0x50, 0x44, 0x46) -> Kind("document", "PDF")
            has(0x49, 0x44, 0x33) -> Kind("audio", "Audio (MP3/ID3)")
            has(0xFF, 0xFB) || has(0xFF, 0xF3) || has(0xFF, 0xF2) -> Kind("audio", "Audio (MP3)")
            len >= 4 && has(0x4F, 0x67, 0x67, 0x53) -> Kind("audio", "Audio (Ogg)")
            has(0x50, 0x4B, 0x03, 0x04) -> Kind("archive", "ZIP/Office/APK")
            has(0x1F, 0x8B) -> Kind("archive", "gzip")
            has(0x42, 0x5A, 0x68) -> Kind("archive", "bzip2")
            has(0x37, 0x7A, 0xBC, 0xAF) -> Kind("archive", "7-Zip")
            has(0x7F, 0x45, 0x4C, 0x46) -> Kind("binary", "ELF executable")
            looksLikeText(buf, off, len) -> textKind(buf, off, len)
            else -> null
        }
    }

    private fun httpBodyOffset(buf: ByteArray, off: Int, len: Int): Int? {
        // Find \r\n\r\n within a bounded header window.
        val max = minOf(len, 4096)
        var i = 0
        while (i + 3 < max) {
            if (buf[off + i] == '\r'.code.toByte() && buf[off + i + 1] == '\n'.code.toByte() &&
                buf[off + i + 2] == '\r'.code.toByte() && buf[off + i + 3] == '\n'.code.toByte())
                return off + i + 4
            i++
        }
        return null
    }

    private fun httpContentType(buf: ByteArray, off: Int, len: Int): Kind? {
        val max = minOf(len, 4096)
        val head = String(buf, off, max, Charsets.ISO_8859_1)
        if (!head.startsWith("HTTP/") && !head.startsWith("GET ") && !head.startsWith("POST ")) return null
        val m = Regex("(?im)^Content-Type:[ \\t]*([^\\r\\n]+)").find(head) ?: return null
        return fromMime(m.groupValues[1])
    }

    private fun looksLikeText(buf: ByteArray, off: Int, len: Int): Boolean {
        val n = minOf(len, 256)
        if (n == 0) return false
        var printable = 0
        for (i in 0 until n) {
            val b = buf[off + i].toInt() and 0xFF
            if (b == 0x09 || b == 0x0A || b == 0x0D || b in 0x20..0x7E) printable++
        }
        return printable.toDouble() / n >= 0.90
    }

    private fun textKind(buf: ByteArray, off: Int, len: Int): Kind {
        val head = String(buf, off, minOf(len, 64), Charsets.ISO_8859_1).trimStart()
        return when {
            head.startsWith("<!DOCTYPE html", true) || head.startsWith("<html", true) -> Kind("text", "HTML")
            head.startsWith("{") || head.startsWith("[") -> Kind("text", "JSON")
            head.startsWith("<?xml") || head.startsWith("<") -> Kind("text", "XML/markup")
            else -> Kind("text", "Text")
        }
    }
}

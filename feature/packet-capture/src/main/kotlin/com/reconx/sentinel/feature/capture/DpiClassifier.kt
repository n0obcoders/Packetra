package com.reconx.sentinel.feature.capture

/**
 * Lightweight deep-packet-inspection: identifies the application-layer protocol
 * of a flow from the first payload bytes plus the destination port — the same
 * heuristic classification Wireshark/nDPI do. It reports whether the payload is
 * ENCRYPTED (TLS, QUIC) so the UI can be honest: an encrypted flow's contents
 * are not readable here and are never decrypted.
 */
object DpiClassifier {

    data class L7(
        val protocol: String,      // e.g. "TLS", "HTTP", "DNS", "QUIC", "SSH"
        val encrypted: Boolean,    // true → payload is ciphertext (no content sniff possible)
        val detail: String? = null // e.g. negotiated TLS record version
    )

    /**
     * @param payload the L4 payload (TCP/UDP data), not the IP/TCP header.
     * @param proto "TCP" or "UDP".
     */
    fun classify(payload: ByteArray, off: Int, len: Int, dstPort: Int, proto: String): L7? {
        if (len <= 0 || off < 0 || off + len > payload.size) return portOnly(dstPort, proto)
        fun at(i: Int) = if (i < len) payload[off + i].toInt() and 0xFF else -1

        // TLS record: content type 20-23, version 03 0x
        if (proto == "TCP" && len >= 3 && at(0) in 0x14..0x17 && at(1) == 0x03 && at(2) in 0x00..0x04) {
            val ver = when (at(2)) {
                0x01 -> "1.0"; 0x02 -> "1.1"; 0x03 -> "1.2/1.3"; else -> "SSL3/?"
            }
            val handshake = if (at(0) == 0x16) " handshake" else ""
            return L7("TLS", encrypted = true, detail = "record v$ver$handshake")
        }
        // Cleartext HTTP request
        if (proto == "TCP" && startsWithMethod(payload, off, len)) return L7("HTTP", encrypted = false)
        // HTTP response
        if (proto == "TCP" && len >= 5 && at(0) == 'H'.code && at(1) == 'T'.code &&
            at(2) == 'T'.code && at(3) == 'P'.code && at(4) == '/'.code)
            return L7("HTTP", encrypted = false, detail = "response")
        // SSH
        if (proto == "TCP" && len >= 4 && at(0) == 'S'.code && at(1) == 'S'.code &&
            at(2) == 'H'.code && at(3) == '-'.code) return L7("SSH", encrypted = true)
        // DNS over UDP/53 or TCP/53
        if (dstPort == 53) return L7("DNS", encrypted = false)
        // QUIC: UDP, long header has high bit set (0x80), and the version/length
        // layout of IETF QUIC. Port 443/UDP is the common case.
        if (proto == "UDP" && (dstPort == 443 || dstPort == 80) && at(0) >= 0x80)
            return L7("QUIC", encrypted = true, detail = "HTTP/3")
        // NTP (UDP/123), common and cleartext
        if (proto == "UDP" && dstPort == 123) return L7("NTP", encrypted = false)
        return portOnly(dstPort, proto)
    }

    private fun startsWithMethod(buf: ByteArray, off: Int, len: Int): Boolean {
        val methods = arrayOf("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")
        val head = String(buf, off, minOf(len, 8), Charsets.ISO_8859_1)
        return methods.any { head.startsWith(it) }
    }

    /** Fall back to a well-known-port guess when no payload signature matched. */
    private fun portOnly(dstPort: Int, proto: String): L7? = when (dstPort) {
        443 -> L7(if (proto == "UDP") "QUIC" else "TLS", encrypted = true)
        80, 8080 -> L7("HTTP", encrypted = false)
        53 -> L7("DNS", encrypted = false)
        853 -> L7("DoT", encrypted = true)       // DNS-over-TLS
        22 -> L7("SSH", encrypted = true)
        123 -> L7("NTP", encrypted = false)
        else -> null
    }
}

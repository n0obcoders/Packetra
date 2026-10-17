package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Pure, passive analysis of the NEGOTIATED TLS cipher suite name (as reported by
 * the handshake — no active cipher enumeration, no downgrade attack). Flags suites
 * known to be weak/deprecated. This only tells us the one suite our own handshake
 * selected; a full cipher audit needs a dedicated TLS scanner, and that caveat is
 * stated rather than implied.
 */
object TlsCipherRules {
    private data class Weak(val needle: String, val why: String)

    private val weak = listOf(
        Weak("_NULL_", "a NULL cipher provides no encryption"),
        Weak("_RC4_", "RC4 is broken (biased keystream) and prohibited (RFC 7465)"),
        Weak("RC4", "RC4 is broken (biased keystream) and prohibited (RFC 7465)"),
        Weak("_DES_", "single DES has a 56-bit key and is trivially brute-forced"),
        Weak("3DES", "3DES is deprecated and exposed to Sweet32 birthday attacks"),
        Weak("DES_CBC3", "3DES is deprecated and exposed to Sweet32 birthday attacks"),
        Weak("_MD5", "MD5-based MACs are collision-prone and deprecated"),
        Weak("EXPORT", "EXPORT-grade ciphers use intentionally crippled key sizes (FREAK/Logjam)"),
        Weak("ANON", "anonymous key exchange offers no server authentication"),
        Weak("_anon_", "anonymous key exchange offers no server authentication"),
    )

    /** @return the reason the negotiated suite is weak, or null if it is acceptable. */
    fun weakness(cipher: String?): String? {
        if (cipher.isNullOrBlank()) return null
        val up = cipher.uppercase()
        weak.forEach { if (up.contains(it.needle.uppercase())) return it.why }
        return null
    }

    fun finding(url: String, cipher: String, why: String): Finding = Finding(
        id = "web-tls-cipher-${url.hashCode().toUInt().toString(16)}",
        title = "Weak TLS cipher negotiated ($cipher)", category = "transport_security",
        severity = Severity.MEDIUM, confidence = Confidence.CONFIRMED, target = url,
        evidence = mapOf("cipher" to cipher),
        explanation = "The handshake negotiated $cipher — $why. (This is the suite our connection " +
            "selected; a complete cipher audit requires a dedicated TLS scanner.)",
        remediation = "Disable weak/legacy cipher suites; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) " +
            "with forward secrecy (ECDHE) on TLS 1.2+.",
        verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
}

/**
 * Pure validation of the HTTP→HTTPS redirect journey observed by [WebAssessor].
 * Given the hop chain it followed and whether the final hop was HTTPS, it checks
 * that a plaintext entry point is promptly upgraded to HTTPS. Passive: it reasons
 * over the chain already captured, issuing no extra requests.
 */
object RedirectChainValidator {
    fun analyze(url: String, chain: List<String>, finalHttps: Boolean): List<Finding> {
        if (chain.isEmpty()) return emptyList()
        val startedHttp = chain.first().startsWith("http://", true)
        if (!startedHttp) return emptyList() // entered over HTTPS already — nothing to validate here
        val upgraded = chain.drop(1).any { it.startsWith("https://", true) } || finalHttps
        if (!upgraded) {
            return listOf(Finding(
                id = "web-redirect-noupgrade-${url.hashCode().toUInt().toString(16)}",
                title = "HTTP entry point is not redirected to HTTPS", category = "transport_security",
                severity = Severity.HIGH, confidence = Confidence.CONFIRMED, target = chain.first(),
                evidence = mapOf("chain" to chain.joinToString(" -> ").take(500)),
                explanation = "The plaintext HTTP URL was served (and followed) without ever upgrading to HTTPS, " +
                    "so credentials and cookies can traverse an unencrypted channel and be stripped or sniffed.",
                remediation = "Redirect all HTTP to HTTPS with a 301/308 before serving any content, and set HSTS.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment"))
        }
        return emptyList()
    }

    /** True when the chain began on HTTP and reached HTTPS — a passed upgrade. */
    fun upgradedCleanly(chain: List<String>, finalHttps: Boolean): Boolean {
        if (chain.isEmpty()) return false
        val startedHttp = chain.first().startsWith("http://", true)
        return startedHttp && (finalHttps || chain.drop(1).any { it.startsWith("https://", true) })
    }
}

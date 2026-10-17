package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Passive client-side asset leakage review. Scans already-fetched HTML/JS text
 * (never executes it) for things front-end builds commonly ship by accident:
 * source maps (which reconstruct original source), and references to internal /
 * staging hosts or hardcoded private IPs that disclose non-production infra.
 * Every signal is a lead to confirm manually, not proof of a breach.
 */
object AssetLeakAnalyzer {

    private val SOURCEMAP = Regex("""(?i)(sourceMappingURL\s*=\s*\S+\.map|["'][^"']+\.js\.map["'])""")
    private val INTERNAL_HOST = Regex(
        """(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)*(?:staging|stage|dev|development|test|testing|uat|qa|preprod|pre-prod|internal|intranet|corp|local)\.[a-z0-9.-]+)""")
    private val LOOPBACK_OR_PRIVATE = Regex(
        """\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?\b""")

    /**
     * @param baseHost the authorized host, so references back to it are not reported as "internal".
     * @param text concatenated HTML + any fetched inline/linked JS.
     */
    fun analyze(url: String, baseHost: String, text: String): List<Finding> {
        val out = mutableListOf<Finding>()

        val maps = SOURCEMAP.findAll(text).map { it.value }.distinct().take(5).toList()
        if (maps.isNotEmpty()) out += Finding(
            id = "web-sourcemap-${url.hashCode().toUInt().toString(16)}",
            title = "Source maps exposed", category = "information_disclosure",
            severity = Severity.LOW, confidence = Confidence.FIRM, target = url,
            evidence = mapOf("references" to maps.joinToString("; ").take(300)),
            explanation = "The site references JavaScript source maps (.map). If served, they reconstruct the " +
                "original, unminified source — including comments and internal logic — for anyone to read.",
            remediation = "Do not deploy .map files to production, or restrict them; strip sourceMappingURL comments " +
                "from production bundles.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")

        val hosts = INTERNAL_HOST.findAll(text).map { it.groupValues[1].lowercase() }
            .filter { !it.equals(baseHost, true) && !it.endsWith(".$baseHost", true) }
            .distinct().take(8).toList()
        if (hosts.isNotEmpty()) out += Finding(
            id = "web-internalhost-${url.hashCode().toUInt().toString(16)}",
            title = "Internal/staging host references in client assets", category = "information_disclosure",
            severity = Severity.LOW, confidence = Confidence.TENTATIVE, target = url,
            evidence = mapOf("hosts" to hosts.joinToString(", ").take(300)),
            explanation = "Client-side code references non-production hostnames (${hosts.take(3).joinToString(", ")}" +
                "${if (hosts.size > 3) "…" else ""}), disclosing internal/staging infrastructure an attacker can target.",
            remediation = "Remove staging/internal endpoints from production bundles; use build-time environment " +
                "configuration so only the production host ships.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")

        val locals = LOOPBACK_OR_PRIVATE.findAll(text).map { it.value }.distinct().take(8).toList()
        if (locals.isNotEmpty()) out += Finding(
            id = "web-privateip-${url.hashCode().toUInt().toString(16)}",
            title = "Hardcoded localhost/private IP in client assets", category = "information_disclosure",
            severity = Severity.INFO, confidence = Confidence.TENTATIVE, target = url,
            evidence = mapOf("addresses" to locals.joinToString(", ").take(300)),
            explanation = "Client-side code contains loopback or RFC1918 addresses (${locals.take(3).joinToString(", ")}" +
                "${if (locals.size > 3) "…" else ""}), usually leftover developer configuration.",
            remediation = "Remove hardcoded internal addresses from shipped JavaScript; inject configuration at build time.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")

        return out
    }

    /** Extracts up to [max] same-origin script URLs from HTML for the runner to fetch and scan. */
    fun scriptUrls(baseUrl: String, body: String, max: Int = 4): List<String> {
        val base = baseUrl.toHttpUrlOrNullSafe() ?: return emptyList()
        val re = Regex("""(?i)<script[^>]+src\s*=\s*["']([^"']+)["']""")
        return re.findAll(body).mapNotNull { m ->
            val raw = m.groupValues[1].trim()
            val resolved = base.resolveSafe(raw) ?: return@mapNotNull null
            if (resolved.hostOrNull()?.equals(base.hostOrNull(), true) == true && resolved.toString().endsWith(".js", true))
                resolved.toString() else null
        }.distinct().take(max).toList()
    }
}

// Small, dependency-light URL helpers so this analyzer stays pure/testable without
// pulling OkHttp into unit tests for the regex paths.
private fun String.toHttpUrlOrNullSafe(): java.net.URI? = runCatching { java.net.URI(this) }.getOrNull()
private fun java.net.URI.resolveSafe(ref: String): java.net.URI? = runCatching { this.resolve(ref) }.getOrNull()
private fun java.net.URI.hostOrNull(): String? = this.host

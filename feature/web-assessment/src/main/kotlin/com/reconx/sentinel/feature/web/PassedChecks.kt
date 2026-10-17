package com.reconx.sentinel.feature.web

/** A security control that was verified and found to be correctly in place. The
 *  "green" counterpart to a Finding, so the report shows what PASSED, not only
 *  what failed. */
data class PassedCheck(val name: String, val detail: String)

/**
 * Pure logic: given the final response's headers, scheme, TLS metadata and the
 * redirect chain, lists the controls that are present and correctly configured.
 * Mirrors the negative checks in [HeaderAnalyzer]/[WebAssessor] so a header only
 * counts as "passed" when it exists AND its value raises no issue.
 */
object PassedChecksAnalyzer {
    fun analyze(
        https: Boolean,
        headers: Map<String, String>,
        tls: TlsInfo?,
        redirectChain: List<String>,
    ): List<PassedCheck> {
        val lower = headers.mapKeys { it.key.lowercase() }
        val out = mutableListOf<PassedCheck>()

        if (https) out += PassedCheck("HTTPS in use", "The final response was served over TLS.")

        for (rule in SecurityHeaderRules.all) {
            val value = lower[rule.header.lowercase()] ?: continue
            val issue = rule.valueIssue?.invoke(value)
            if (issue == null)
                out += PassedCheck("${rule.header} present", shortValue(rule.header, value))
        }

        // Content-Security-Policy present AND free of the dangerous patterns CspAnalyzer flags.
        lower["content-security-policy"]?.let { csp ->
            if (CspAnalyzer.analyze("", csp).isEmpty())
                out += PassedCheck("CSP has no dangerous directives",
                    "No wildcard sources, unsafe-inline or unsafe-eval detected.")
        }

        // Cookies: Secure + HttpOnly observed on the joined Set-Cookie.
        lower["set-cookie"]?.let { c ->
            if (c.contains("secure", true)) out += PassedCheck("Cookie Secure flag", "Set-Cookie carried Secure.")
            if (c.contains("httponly", true)) out += PassedCheck("Cookie HttpOnly flag", "Set-Cookie carried HttpOnly.")
            if (c.contains("samesite", true)) out += PassedCheck("Cookie SameSite", "Set-Cookie carried SameSite.")
        }

        // No implementation-disclosing headers.
        if (SecurityHeaderRules.disclosureHeaders.none { lower.containsKey(it.lowercase()) })
            out += PassedCheck("No version-disclosing headers", "Server/X-Powered-By not advertised.")

        // TLS posture.
        tls?.let { t ->
            if (t.legacyProtocols.isEmpty())
                out += PassedCheck("No legacy TLS 1.0/1.1", "Server did not negotiate deprecated TLS versions (where testable).")
            if (TlsCipherRules.weakness(t.cipher) == null && t.cipher.isNotBlank())
                out += PassedCheck("Strong cipher suite", t.cipher)
            t.daysToExpiry?.let { d -> if (d > 21) out += PassedCheck("Certificate validity", "Expires in $d day(s).") }
        }

        if (RedirectChainValidator.upgradedCleanly(redirectChain, https))
            out += PassedCheck("HTTP upgraded to HTTPS", "The plaintext entry point redirected to HTTPS.")

        return out.distinctBy { it.name }
    }

    private fun shortValue(header: String, value: String): String {
        val v = value.trim().replace("\n", " ")
        return if (v.length > 80) "${v.take(77)}…" else v
    }
}

package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Pure logic: turns a map of response headers (+ the final URL and whether the
 * connection was HTTPS) into findings. No network here, so it is fully
 * unit-testable; [WebAssessor] supplies the live headers.
 */
object HeaderAnalyzer {
    fun analyze(url: String, https: Boolean, headers: Map<String, String>): List<Finding> {
        val lower = headers.mapKeys { it.key.lowercase() }
        val out = mutableListOf<Finding>()

        for (rule in SecurityHeaderRules.all) {
            val value = lower[rule.header.lowercase()]
            if (value == null) {
                out += finding(url, rule.title, "security_header", rule.severityIfMissing,
                    Confidence.CONFIRMED, "Response did not include ${rule.header}.", rule.remediation,
                    mapOf("header" to rule.header, "present" to "false"))
            } else rule.valueIssue?.invoke(value)?.let { issue ->
                out += finding(url, "${rule.header} weak configuration", "security_header",
                    Severity.LOW, Confidence.FIRM, issue, rule.remediation,
                    mapOf("header" to rule.header, "value" to value))
            }
        }

        // Deep analysis of a PRESENT Content-Security-Policy (wildcard subdomain trust, unsafe-inline, etc.).
        lower["content-security-policy"]?.let { csp -> out += CspAnalyzer.analyze(url, csp) }

        for (h in SecurityHeaderRules.disclosureHeaders) {
            lower[h.lowercase()]?.let { v ->
                out += finding(url, "Information disclosure via $h", "information_disclosure",
                    Severity.INFO, Confidence.CONFIRMED,
                    "The $h header reveals implementation detail ('$v').",
                    "Remove or genericise the $h header.", mapOf("header" to h, "value" to v))
            }
        }

        // Cookie attribute checks (Set-Cookie may appear multiple times; joined here).
        lower["set-cookie"]?.let { cookie ->
            if (!cookie.contains("secure", true) && https)
                out += finding(url, "Cookie without Secure attribute", "cookie_security",
                    Severity.MEDIUM, Confidence.FIRM, "A Set-Cookie over HTTPS lacked the Secure flag.",
                    "Add the Secure attribute to session cookies.", mapOf("evidence" to "<redacted-cookie>"))
            if (!cookie.contains("httponly", true))
                out += finding(url, "Cookie without HttpOnly attribute", "cookie_security",
                    Severity.LOW, Confidence.FIRM, "A Set-Cookie lacked the HttpOnly flag.",
                    "Add HttpOnly to cookies not needed by client-side script.",
                    mapOf("evidence" to "<redacted-cookie>"))
        }

        if (!https)
            out += finding(url, "Endpoint served over plaintext HTTP", "transport_security",
                Severity.MEDIUM, Confidence.CONFIRMED, "The URL was reachable over unencrypted HTTP.",
                "Serve exclusively over HTTPS and redirect HTTP to HTTPS.", mapOf("scheme" to "http"))

        return out
    }

    private fun finding(url: String, title: String, cat: String, sev: Severity,
                        conf: Confidence, explanation: String, remediation: String,
                        evidence: Map<String, String>) = Finding(
        id = "web-${title.hashCode().toUInt().toString(16)}-${url.hashCode().toUInt().toString(16)}",
        title = title, category = cat, severity = sev, confidence = conf, target = url,
        evidence = evidence, explanation = explanation, remediation = remediation,
        verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
}

package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Severity

/**
 * Declarative catalogue of the non-destructive security-header checks (spec §9).
 * Each rule is pure data; [HeaderAnalyzer] applies it to a response's headers.
 * This is intentionally a passive configuration review of what the server sends.
 */
data class HeaderRule(
    val header: String,
    val title: String,
    val severityIfMissing: Severity,
    val remediation: String,
    /** optional predicate on the header value when PRESENT (returns an issue or null) */
    val valueIssue: ((String) -> String?)? = null,
)

object SecurityHeaderRules {
    val all: List<HeaderRule> = listOf(
        HeaderRule("Strict-Transport-Security", "HSTS not set", Severity.MEDIUM,
            "Add Strict-Transport-Security with a max-age of at least 31536000.") { v ->
            val m = Regex("max-age=(\\d+)").find(v)?.groupValues?.get(1)?.toLongOrNull()
            if (m == null || m < 15552000) "max-age is missing or shorter than 180 days" else null
        },
        HeaderRule("Content-Security-Policy", "Content-Security-Policy missing", Severity.MEDIUM,
            "Define a CSP to constrain script/style/object sources."),
        HeaderRule("X-Content-Type-Options", "X-Content-Type-Options missing", Severity.LOW,
            "Set X-Content-Type-Options: nosniff.") { v ->
            if (!v.equals("nosniff", true)) "value is not 'nosniff'" else null
        },
        HeaderRule("X-Frame-Options", "Clickjacking protection missing", Severity.LOW,
            "Set X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive."),
        HeaderRule("Referrer-Policy", "Referrer-Policy missing", Severity.INFO,
            "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin."),
        HeaderRule("Permissions-Policy", "Permissions-Policy not set", Severity.LOW,
            "Add a Permissions-Policy that restricts powerful features, e.g. " +
                "geolocation=(), camera=(), microphone=(), payment=().") { v ->
            // Present but leaves a powerful feature wide open (feature=* or no restriction).
            val lower = v.lowercase()
            val open = listOf("geolocation", "camera", "microphone", "payment").filter { feat ->
                Regex("$feat\\s*=\\s*\\*").containsMatchIn(lower)
            }
            if (open.isNotEmpty()) "grants ${open.joinToString(", ")} to all origins (=*)" else null
        },
    )

    /** Headers whose PRESENCE discloses implementation detail (informational). */
    val disclosureHeaders = listOf("Server", "X-Powered-By", "X-AspNet-Version")
}

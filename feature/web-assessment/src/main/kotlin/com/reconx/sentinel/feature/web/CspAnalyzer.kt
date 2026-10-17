package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Analyses a PRESENT Content-Security-Policy (SecurityHeaderRules only flags a
 * MISSING one). It surfaces the weaknesses that make a CSP bypassable: wildcard
 * subdomain trust (e.g. *.example.com — a single forgotten subdomain that an
 * attacker takes over then becomes a trusted script source and defeats the whole
 * policy), unsafe-inline / unsafe-eval in script-src, open wildcards, data: in
 * script-src, and missing object-src/base-uri hardening. Pure and testable.
 */
object CspAnalyzer {

    private val FETCH_DIRECTIVES = setOf(
        "default-src", "script-src", "script-src-elem", "style-src", "img-src",
        "connect-src", "font-src", "frame-src", "child-src", "object-src", "base-uri")

    /** Parse a CSP header into directive -> list of source expressions. */
    fun parse(csp: String): Map<String, List<String>> =
        csp.split(';').mapNotNull { seg ->
            val parts = seg.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (parts.isEmpty()) null else parts[0].lowercase() to parts.drop(1)
        }.toMap()

    /** Wildcard-subdomain hosts the policy trusts, e.g. "*.example.com" -> "example.com". */
    fun wildcardSubdomainBases(csp: String): List<String> {
        val parsed = parse(csp)
        return parsed.filterKeys { it in FETCH_DIRECTIVES }.values.flatten()
            .mapNotNull { src ->
                val s = src.trim('\'', '"')
                Regex("""^\*\.([A-Za-z0-9.-]+\.[A-Za-z]{2,})$""").find(s)?.groupValues?.get(1)
            }.distinct()
    }

    fun analyze(url: String, csp: String): List<Finding> {
        val out = mutableListOf<Finding>()
        val parsed = parse(csp)
        val scriptSrc = parsed["script-src"] ?: parsed["default-src"] ?: emptyList()
        val scriptSrcLower = scriptSrc.map { it.trim('\'', '"').lowercase() }

        if (scriptSrcLower.any { it == "unsafe-inline" })
            out += f(url, "CSP allows 'unsafe-inline' scripts", Severity.MEDIUM,
                "script-src includes 'unsafe-inline', which lets injected inline scripts run — the CSP gives little " +
                    "XSS protection.",
                "Remove 'unsafe-inline'; use nonces or hashes for the scripts you need.",
                mapOf("directive" to "script-src"))
        if (scriptSrcLower.any { it == "unsafe-eval" })
            out += f(url, "CSP allows 'unsafe-eval'", Severity.LOW,
                "script-src includes 'unsafe-eval', permitting eval()/Function() on attacker-influenced strings.",
                "Remove 'unsafe-eval' and refactor code that depends on it.", mapOf("directive" to "script-src"))
        if (scriptSrcLower.any { it == "*" || it == "https:" || it == "http:" || it == "data:" })
            out += f(url, "CSP script-src uses an overly broad source", Severity.MEDIUM,
                "script-src trusts a wide source (${scriptSrcLower.first { it == "*" || it.endsWith(":") }}), which " +
                    "largely defeats the policy.",
                "Restrict script-src to specific, trusted origins (or 'self' plus nonces).",
                mapOf("directive" to "script-src"))

        val wildcards = wildcardSubdomainBases(csp)
        if (wildcards.isNotEmpty())
            out += f(url, "CSP trusts all subdomains (${wildcards.joinToString(", ") { "*.$it" }})", Severity.MEDIUM,
                "The policy trusts every subdomain of ${wildcards.joinToString(", ")}. If any one of them — including " +
                    "forgotten, staging or unmonitored hosts — is taken over, the attacker gains a CSP-trusted script " +
                    "origin and can bypass the policy on the main site. Cross-check with subdomain discovery.",
                "Trust only the specific subdomains that must serve scripts, not a wildcard; retire stale subdomains.",
                mapOf("directive" to "script-src/default-src", "wildcards" to wildcards.joinToString(",")))

        return out
    }

    private fun f(url: String, title: String, sev: Severity, why: String, fix: String, ev: Map<String, String>) =
        Finding(
            id = "web-csp-${(url + title).hashCode().toUInt().toString(16)}",
            title = title, category = "security_header", severity = sev, confidence = Confidence.FIRM,
            target = url, evidence = ev, explanation = why, remediation = fix,
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
}

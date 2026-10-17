package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Passive cookie-security analysis from Set-Cookie headers already returned.
 * Flags missing Secure / HttpOnly / SameSite attributes on each cookie. Pure and
 * unit-testable; it never sets or sends cookies.
 */
object CookieAnalyzer {
    /** @param setCookies raw Set-Cookie header values. */
    fun analyze(url: String, https: Boolean, setCookies: List<String>): List<Finding> {
        val out = mutableListOf<Finding>()
        for (raw in setCookies) {
            val name = raw.substringBefore('=').trim()
            if (name.isEmpty()) continue
            val attrs = raw.split(';').drop(1).map { it.trim().lowercase() }
            val hasSecure = attrs.any { it == "secure" }
            val hasHttpOnly = attrs.any { it == "httponly" }
            val sameSite = attrs.firstOrNull { it.startsWith("samesite=") }?.substringAfter('=')
            val missing = buildList {
                if (https && !hasSecure) add("Secure")
                if (!hasHttpOnly) add("HttpOnly")
                if (sameSite == null) add("SameSite")
            }
            if (missing.isNotEmpty()) out += Finding(
                id = "web-cookie-${(url + name).hashCode().toUInt().toString(16)}",
                title = "Cookie '$name' missing ${missing.joinToString("/")}",
                category = "session_security",
                severity = if ("HttpOnly" in missing || (https && "Secure" in missing)) Severity.MEDIUM else Severity.LOW,
                confidence = Confidence.FIRM, target = url,
                evidence = mapOf("cookie" to name, "missing" to missing.joinToString(",")),
                explanation = "The cookie is set without ${missing.joinToString(", ")}, weakening its protection " +
                    "against theft (XSS), transport exposure or CSRF.",
                remediation = "Set Secure (HTTPS only), HttpOnly (no script access) and SameSite=Lax/Strict as appropriate.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment",
            )
        }
        return out
    }
}

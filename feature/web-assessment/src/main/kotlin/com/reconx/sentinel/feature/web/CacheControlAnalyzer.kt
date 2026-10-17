package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Flags sensitive responses that fail to forbid caching. A page that returns
 * user/authenticated data but lacks `Cache-Control: no-store`/`no-cache` can be
 * retained by shared proxies, the browser disk cache or the back button, leaking
 * personal data on shared machines (CWE-525). Pure: the caller decides whether a
 * route looks sensitive and passes the relevant header values.
 */
object CacheControlAnalyzer {

    /** Path or response signals that the route likely serves user/authenticated data. */
    private val SENSITIVE_PATH = Regex(
        "(?i)(account|admin|dashboard|profile|settings|billing|invoice|payment|checkout|" +
            "orders?|messages?|inbox|user(s)?|member|wallet|transactions?|token|session|auth|login|logout|api)")

    /** Decide sensitivity from the URL path and whether the response set a session cookie. */
    fun looksSensitive(path: String, setsSessionCookie: Boolean, body: String): Boolean {
        if (setsSessionCookie) return true
        if (SENSITIVE_PATH.containsMatchIn(path)) return true
        // Authenticated-page markers in the body.
        return body.contains("logout", true) &&
            (body.contains("account", true) || body.contains("profile", true) || body.contains("dashboard", true))
    }

    /** Returns a finding when a sensitive route does not forbid caching. */
    fun analyze(url: String, cacheControl: String?, pragma: String?, sensitive: Boolean): Finding? {
        if (!sensitive) return null
        val cc = cacheControl?.lowercase() ?: ""
        val forbidsStore = cc.contains("no-store")
        val forbidsCache = cc.contains("no-cache") || pragma?.contains("no-cache", true) == true
        val isPrivate = cc.contains("private")
        if (forbidsStore) return null
        // no-store missing: still weaker if only private/no-cache present.
        val detail = when {
            cc.isBlank() && pragma.isNullOrBlank() ->
                "No Cache-Control header on a sensitive response — proxies and the browser may cache user data."
            !forbidsCache && isPrivate ->
                "Cache-Control is '$cacheControl' (private but not no-store); the browser can still persist it to disk."
            !forbidsCache ->
                "Cache-Control is '$cacheControl' and does not include no-store/no-cache."
            else ->
                "Cache-Control is '$cacheControl'; it allows caching (no 'no-store') for a response that looks sensitive."
        }
        return Finding(
            id = "web-cachecontrol-${url.hashCode().toUInt().toString(16)}",
            title = "Sensitive response may be cached",
            category = "information_disclosure",
            severity = if (cc.isBlank()) Severity.MEDIUM else Severity.LOW,
            confidence = Confidence.TENTATIVE,
            target = url,
            evidence = mapOf("cache_control" to (cacheControl ?: "(absent)"), "pragma" to (pragma ?: "(absent)")),
            explanation = detail,
            remediation = "Return `Cache-Control: no-store, no-cache, must-revalidate` (and `Pragma: no-cache`) on " +
                "authenticated or user-specific responses.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
    }
}

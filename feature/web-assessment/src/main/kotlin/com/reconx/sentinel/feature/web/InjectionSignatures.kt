package com.reconx.sentinel.feature.web

/**
 * Pure signature matchers for LIGHTWEIGHT injection signals. The runner sends a
 * single benign probe per query parameter (GET only) and uses these to decide if
 * the response merely HINTS at a weakness. Deliberately conservative: these are
 * TENTATIVE signals to confirm manually, never exploits. No payload is weaponised
 * — the XSS marker is an inert token, the SQL probe is a lone quote, and the
 * open-redirect probe is a canary hostname.
 */
object InjectionSignatures {
    /** A unique inert token used to detect whether input is reflected unencoded. */
    fun marker(seed: Int): String = "rxs${(seed.toUInt() % 100000u)}zz"

    /** True if the marker is reflected verbatim (unencoded) in the body. */
    fun reflectedUnencoded(body: String, marker: String): Boolean = body.contains(marker)

    /** True if the marker appears inside an HTML tag/attribute/script context where
     *  it could break out (a stronger reflected-XSS hint than mere reflection). */
    fun reflectedInDangerousContext(body: String, marker: String): Boolean {
        val i = body.indexOf(marker)
        if (i < 0) return false
        val around = body.substring((i - 40).coerceAtLeast(0), (i + marker.length + 10).coerceAtMost(body.length))
        return around.contains("<") || around.contains("javascript:", true) ||
            around.contains("on", true) && around.contains("=") || around.contains("<script", true)
    }

    private val SQL_ERRORS = listOf(
        "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
        "unclosed quotation mark after the character string", "quoted string not properly terminated",
        "pg_query", "postgresql", "sqlite_", "sqlstate", "ora-0", "odbc sql server driver",
        "microsoft ole db provider for sql server", "syntax error at or near",
    )

    /** Returns the matched SQL-error signature if the body looks like a DB error. */
    fun sqlError(body: String): String? {
        val b = body.lowercase()
        return SQL_ERRORS.firstOrNull { b.contains(it) }
    }

    /** True if a redirect Location points to our canary host (open redirect). */
    fun openRedirectTo(location: String?, canaryHost: String): Boolean {
        if (location == null) return false
        val l = location.trim()
        return l.startsWith("http://$canaryHost", true) || l.startsWith("https://$canaryHost", true) ||
            l.startsWith("//$canaryHost", true)
    }
}

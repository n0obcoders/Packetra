package com.reconx.sentinel.feature.web

/**
 * A SMALL, static set of end-of-life / clearly-outdated version thresholds for
 * common server software AND client-side JS libraries, used to flag outdated
 * components from passive fingerprinting. This is NOT a live CVE database — it is
 * a conservative, offline hint that a version is old enough to warrant a manual
 * NVD/vendor check. Honest by design: it reports "outdated, verify against NVD",
 * and for libraries with well-known historical vulnerability classes it names the
 * class (e.g. XSS, prototype pollution) as context — never a specific CVE claim.
 */
object VersionRules {
    // name (lowercase) -> minimum version still considered current.
    // Longest matching key wins, so "jquery ui" is not matched by the "jquery" rule.
    private val MIN_SUPPORTED = linkedMapOf(
        "nginx" to listOf(1, 24),
        "apache" to listOf(2, 4),
        "openssl" to listOf(3, 0),
        "php" to listOf(8, 1),
        "tomcat" to listOf(9, 0),
        // Client-side libraries
        "jquery ui" to listOf(1, 13, 2),
        "jquery" to listOf(3, 5, 0),
        "lodash" to listOf(4, 17, 21),
        "underscore" to listOf(1, 13, 0),
        "bootstrap" to listOf(4, 0, 0),
        "angularjs" to listOf(1, 999),   // AngularJS (1.x) is end-of-life; any 1.x is outdated
        "vue" to listOf(2, 7, 0),
        "moment" to listOf(2, 29, 4),
        "handlebars" to listOf(4, 7, 7),
        "dompurify" to listOf(2, 4, 0),
    )

    // Known historical vulnerability class, added to the message as context (not a CVE claim).
    private val KNOWN_ISSUE = mapOf(
        "jquery" to "older jQuery has known XSS issues (fixed in 3.5.0)",
        "lodash" to "older Lodash has known prototype-pollution issues (fixed in 4.17.21)",
        "bootstrap" to "Bootstrap 3.x has known XSS issues in data-* attributes",
        "angularjs" to "AngularJS 1.x reached end-of-life (no security fixes)",
        "moment" to "older Moment.js has a known ReDoS issue (fixed in 2.29.4)",
        "handlebars" to "older Handlebars has known prototype-pollution issues",
    )

    /** Returns a human reason if the tech's version is below the supported line. */
    fun outdated(name: String, version: String?): String? {
        if (version == null) return null
        val n = name.trim().lowercase()
        val key = MIN_SUPPORTED.keys.filter { n.contains(it) }.maxByOrNull { it.length } ?: return null
        val min = MIN_SUPPORTED[key]!!
        val parts = version.split('.', '-', '_').mapNotNull { it.takeWhile(Char::isDigit).toIntOrNull() }
        if (parts.isEmpty()) return null
        if (compareVersion(parts, min) >= 0) return null
        val extra = KNOWN_ISSUE[key]?.let { " — $it" } ?: ""
        return "$name $version is below the current supported line (${min.joinToString(".")}+)$extra; " +
            "check it against NVD for known CVEs and update."
    }

    private fun compareVersion(a: List<Int>, b: List<Int>): Int {
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }; val y = b.getOrElse(i) { 0 }
            if (x != y) return x - y
        }
        return 0
    }
}

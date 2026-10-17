package com.reconx.sentinel.feature.web

/**
 * Pure parser for robots.txt. robots.txt often lists Disallow paths that point
 * straight at admin panels, internal tools and backups the owner would rather
 * keep quiet — a classic recon shortcut. This extracts the Disallow paths and
 * highlights the interesting ones. Reading a published file is passive.
 */
object RobotsAnalyzer {

    private val INTERESTING = Regex(
        "(?i)(admin|administrator|wp-admin|phpmyadmin|manage|manager|console|dashboard|backend|internal|" +
            "private|secret|config|backup|\\.git|\\.env|api|staging|test|dev|cpanel|webmail|login|auth)")

    /** All Disallow paths, in order, de-duplicated. */
    fun disallowPaths(robots: String): List<String> =
        robots.lineSequence()
            .map { it.substringBefore('#').trim() }
            .filter { it.regionMatches(0, "Disallow:", 0, 9, ignoreCase = true) }
            .map { it.substring(9).trim() }
            .filter { it.isNotEmpty() && it != "/" }
            .distinct()
            .toList()

    /** Disallow paths that look sensitive (admin/internal/backup/etc). */
    fun interestingDisallows(robots: String): List<String> =
        disallowPaths(robots).filter { INTERESTING.containsMatchIn(it) }
}

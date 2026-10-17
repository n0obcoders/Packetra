package com.reconx.sentinel.core.security

/**
 * Removes secrets from any text before it is logged, stored in a report, or
 * sent to analytics (spec §10 "never store real passwords", §17 log redaction).
 * Conservative: redact on any match, keep enough shape to be useful.
 */
object Redactor {
    private val patterns: List<Pair<Regex, String>> = listOf(
        Regex("""(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+""") to "$1<redacted-token>",
        Regex("""(?i)(password"?\s*[:=]\s*"?)[^"\s,}]+""") to "$1<redacted>",
        Regex("""(?i)(api[_-]?key"?\s*[:=]\s*"?)[^"\s,}]+""") to "$1<redacted>",
        Regex("""(?i)(secret"?\s*[:=]\s*"?)[^"\s,}]+""") to "$1<redacted>",
        Regex("""eyJ[A-Za-z0-9._\-]{10,}""") to "<redacted-jwt>",
        Regex("""AKIA[0-9A-Z]{16}""") to "<redacted-aws-key>",
    )

    fun redact(input: String): String =
        patterns.fold(input) { acc, (re, repl) -> re.replace(acc, repl) }

    /** Never echo a credential: return only whether it was non-empty + its length. */
    fun describeSecret(secret: String): String =
        if (secret.isEmpty()) "<empty>" else "<set:${secret.length} chars>"
}

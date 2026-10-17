package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Passive client-side secret scanning. Runs regex detectors over already-fetched
 * HTML, linked JavaScript and source maps to surface hardcoded credentials —
 * API keys, cloud keys, tokens, private keys — that front-end builds sometimes
 * ship by accident (CWE-798 / CWE-615). It reads text the server already served
 * publicly; it never executes code or sends the secret anywhere. Matched values
 * are REDACTED in findings so the report itself does not store the live secret.
 */
object SecretScanner {

    data class Rule(val name: String, val regex: Regex, val severity: Severity, val group: Int = 0)
    data class Hit(val rule: String, val severity: Severity, val redacted: String)

    private val RULES = listOf(
        Rule("AWS access key ID", Regex("""\bAKIA[0-9A-Z]{16}\b"""), Severity.HIGH),
        Rule("AWS session/temp key", Regex("""\b(?:ASIA)[0-9A-Z]{16}\b"""), Severity.HIGH),
        Rule("Google API key", Regex("""\bAIza[0-9A-Za-z_\-]{35}\b"""), Severity.HIGH),
        Rule("Google OAuth token", Regex("""\bya29\.[0-9A-Za-z_\-]{20,}"""), Severity.HIGH),
        Rule("GitHub token", Regex("""\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"""), Severity.HIGH),
        Rule("GitHub fine-grained PAT", Regex("""\bgithub_pat_[0-9A-Za-z_]{22,}\b"""), Severity.HIGH),
        Rule("Slack token", Regex("""\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"""), Severity.HIGH),
        Rule("Slack webhook", Regex("""https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"""), Severity.MEDIUM),
        Rule("Stripe secret key", Regex("""\bsk_live_[0-9A-Za-z]{20,}\b"""), Severity.CRITICAL),
        Rule("Stripe restricted key", Regex("""\brk_live_[0-9A-Za-z]{20,}\b"""), Severity.HIGH),
        Rule("SendGrid API key", Regex("""\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"""), Severity.HIGH),
        Rule("Twilio API key", Regex("""\bSK[0-9a-fA-F]{32}\b"""), Severity.MEDIUM),
        Rule("Private key block", Regex("""-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"""), Severity.CRITICAL),
        Rule("JWT", Regex("""\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"""), Severity.MEDIUM),
        Rule("Credentials in URL", Regex("""\bhttps?://[^/\s:@"']+:[^/\s:@"']+@[^/\s"']+"""), Severity.HIGH),
        // Generic assignment — kept last and reported TENTATIVE because it over-matches.
        Rule("Generic hardcoded secret",
            Regex("""(?i)(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)["']?\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{12,})["']"""),
            Severity.MEDIUM, group = 1),
    )

    private val PLACEHOLDER = Regex(
        "(?i)^(?:x+|0+|1234.*|your[_-].*|my[_-].*|example.*|sample.*|test.*|demo.*|changeme|placeholder|" +
            "none|null|undefined|true|false|abc.*|foo.*|bar.*|xxx.*|\\*+|\\.+|lorem.*)$")

    /** Pure detection over arbitrary text. */
    fun findSecrets(text: String): List<Hit> {
        val seen = LinkedHashSet<String>()
        val hits = mutableListOf<Hit>()
        for (rule in RULES) {
            for (m in rule.regex.findAll(text)) {
                val raw = (if (rule.group > 0) m.groupValues.getOrNull(rule.group) else m.value)?.trim().orEmpty()
                if (raw.length < 8) continue
                if (rule.name == "Generic hardcoded secret") {
                    if (PLACEHOLDER.matches(raw)) continue
                    // Require some entropy: at least one digit and one letter.
                    if (!(raw.any(Char::isDigit) && raw.any(Char::isLetter))) continue
                }
                val key = rule.name + "|" + raw
                if (!seen.add(key)) continue
                hits += Hit(rule.name, rule.severity, redact(raw))
                if (hits.size >= 50) return hits
            }
        }
        return hits
    }

    /** Scan text and map hits to findings against [sourceUrl]. */
    fun scan(sourceUrl: String, text: String): List<Finding> = findSecrets(text).map { hit ->
        val generic = hit.rule == "Generic hardcoded secret"
        Finding(
            id = "web-secret-${(sourceUrl + hit.rule + hit.redacted).hashCode().toUInt().toString(16)}",
            title = "Hardcoded secret in client assets: ${hit.rule}",
            category = "secret_exposure", severity = hit.severity,
            confidence = if (generic) Confidence.TENTATIVE else Confidence.FIRM,
            target = sourceUrl,
            evidence = mapOf("type" to hit.rule, "match" to hit.redacted),
            explanation = "A value matching ${hit.rule} was found in client-side code served to every visitor" +
                (if (generic) " (generic pattern — confirm it is a real credential, not a placeholder)." else
                    ". Anyone can read it and use it directly."),
            remediation = "Remove the secret from client code, rotate/revoke it immediately, and move it behind a " +
                "server-side proxy or environment configuration. Treat it as compromised once it shipped to a browser.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
    }

    /** Keep a short prefix, mask the rest — enough to recognise, not enough to reuse. */
    private fun redact(s: String): String {
        if (s.length <= 8) return s.take(2) + "****"
        return s.take(4) + "****" + s.takeLast(2) + " (len ${s.length})"
    }
}

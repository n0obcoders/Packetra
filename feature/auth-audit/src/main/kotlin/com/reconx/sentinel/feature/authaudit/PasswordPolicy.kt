package com.reconx.sentinel.feature.authaudit

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/** A declared password policy, as entered from a system's documented settings. */
data class PasswordPolicy(
    val minLength: Int,
    val requiresMfa: Boolean,
    val lockoutThreshold: Int?,     // failed attempts before lockout, null = none
    val rateLimited: Boolean,
    val maxAgeDays: Int?,           // forced rotation; null = none
    val blocksBreachedPasswords: Boolean,
)

/**
 * Evaluates a DECLARED policy against modern (NIST SP 800-63B-style) guidance.
 * Pure logic, fully offline — this is a configuration review, not an attack.
 */
object PasswordPolicyAuditor {
    fun audit(system: String, p: PasswordPolicy): List<Finding> {
        val out = mutableListOf<Finding>()
        fun add(title: String, sev: Severity, why: String, fix: String) {
            out += Finding(
                id = "authpol-${(system + title).hashCode().toUInt().toString(16)}",
                title = title, category = "authentication", severity = sev,
                confidence = Confidence.FIRM, target = system, explanation = why,
                remediation = fix, verification = Verification.VALIDATED_SAFELY,
                source = "auth-audit")
        }
        if (p.minLength < 8)
            add("Minimum password length below 8", Severity.HIGH,
                "Declared minimum length is ${p.minLength}.", "Require at least 8 (ideally 12+) characters.")
        if (!p.requiresMfa)
            add("MFA not required", Severity.HIGH,
                "The system does not require multi-factor authentication.",
                "Require MFA, at least for privileged and remote access.")
        if (p.lockoutThreshold == null && !p.rateLimited)
            add("No lockout or rate limiting", Severity.MEDIUM,
                "Neither account lockout nor rate limiting is configured.",
                "Add rate limiting and/or a lockout/backoff policy to slow online guessing.")
        if (!p.blocksBreachedPasswords)
            add("Breached-password screening absent", Severity.MEDIUM,
                "Known-breached passwords are not rejected.",
                "Screen new passwords against a breached-password corpus.")
        if (p.maxAgeDays != null && p.maxAgeDays in 1..89)
            add("Forced frequent password rotation", Severity.LOW,
                "Rotation every ${p.maxAgeDays} days encourages weak, incremental passwords.",
                "Drop mandatory periodic rotation; rotate only on indication of compromise.")
        return out
    }
}

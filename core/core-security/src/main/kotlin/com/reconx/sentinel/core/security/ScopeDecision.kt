package com.reconx.sentinel.core.security

/** The result of validating a target. [allowed] is the only gate engines read. */
data class ScopeDecision(
    val target: String,
    val allowed: Boolean,
    val reason: String,
    val matchedRule: String? = null,
) {
    companion object {
        fun deny(target: String, reason: String) = ScopeDecision(target, false, reason)
        fun allow(target: String, rule: String) =
            ScopeDecision(target, true, "in scope", rule)
    }
}

package com.reconx.sentinel.core.common

/** Risk severity, kept deliberately separate from [Confidence] (spec §9, §14). */
enum class Severity(val rank: Int) {
    INFO(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

    companion object {
        fun fromString(v: String): Severity =
            entries.firstOrNull { it.name.equals(v, ignoreCase = true) } ?: INFO
    }
}

/** How sure we are a finding is real. Never conflate with [Severity]. */
enum class Confidence { TENTATIVE, FIRM, CONFIRMED }

/** Whether an observation was actively verified, and if so, how safely. */
enum class Verification { UNVERIFIED, VALIDATED_SAFELY, CONFIRMED }

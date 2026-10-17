package com.reconx.sentinel.feature.authaudit

/**
 * No-traffic simulation of how an online password-guessing attack (Hydra-style)
 * would fare against a given authentication configuration, and how defenses stop
 * it. This sends NOTHING over the network — it is a teaching/modelling tool so a
 * defender can reason about lockout, rate limiting and MFA. It deliberately does
 * not perform, and cannot be turned into, a live attack.
 */
object BruteForceSimulation {
    data class Scenario(
        val candidatePasswords: Int,   // size of the guess list the attacker would try
        val guessesPerMinute: Int,     // attacker's raw rate before any defense
        val lockoutThreshold: Int?,    // failed attempts before the account locks (null = none)
        val lockoutMinutes: Int,       // how long a lockout lasts
        val rateLimitPerMinute: Int?,  // server-enforced attempts/min (null = none)
        val mfaEnabled: Boolean,
        val correctGuessIndex: Int?,   // where the real password sits in the list (for the demo); null = not in list
    )

    data class Outcome(
        val wouldSucceed: Boolean,
        val attemptsBeforeBlocked: Int,
        val effectiveGuessesPerMinute: Int,
        val estimatedMinutesToExhaust: Long,
        val stoppedBy: String,
        val narrative: List<String>,
        val defensiveFindings: List<String>,
    )

    fun run(s: Scenario): Outcome {
        val narrative = mutableListOf<String>()
        val defense = mutableListOf<String>()

        if (s.mfaEnabled) {
            narrative += "MFA is enabled: even a correct password does not grant access without the second factor."
            defense += "MFA present — online password guessing alone cannot take over the account."
        }

        // How far can the attacker get before a defense stops them?
        val lockoutStop = s.lockoutThreshold
        val effectiveRate = when {
            s.rateLimitPerMinute != null -> minOf(s.guessesPerMinute, s.rateLimitPerMinute)
            else -> s.guessesPerMinute
        }
        if (s.rateLimitPerMinute != null)
            defense += "Rate limiting caps the attacker at ${s.rateLimitPerMinute} guesses/min (raw ${s.guessesPerMinute})."
        else
            defense += "No server rate limit — attacker runs at their full ${s.guessesPerMinute} guesses/min."

        val attemptsBeforeBlocked = lockoutStop ?: s.candidatePasswords
        val stoppedBy = when {
            s.mfaEnabled -> "MFA (second factor required)"
            lockoutStop != null -> "account lockout after $lockoutStop failed attempts (${s.lockoutMinutes} min)"
            else -> "nothing — the list runs to completion"
        }
        if (lockoutStop == null) defense += "No account lockout — nothing halts repeated guessing."

        val reachable = minOf(attemptsBeforeBlocked, s.candidatePasswords)
        val found = s.correctGuessIndex != null && s.correctGuessIndex < reachable
        val wouldSucceed = found && !s.mfaEnabled

        val minutesToExhaust = if (effectiveRate <= 0) Long.MAX_VALUE
            else Math.ceil(s.candidatePasswords.toDouble() / effectiveRate).toLong()

        narrative += "Attacker list: ${s.candidatePasswords} candidates at ~$effectiveRate effective guesses/min."
        narrative += "Reachable before a block: $reachable attempt(s). Stopped by: $stoppedBy."
        narrative += if (wouldSucceed)
            "RESULT: the correct password (position ${s.correctGuessIndex}) is reached before any block — this config is guessable."
        else if (s.mfaEnabled)
            "RESULT: blocked by MFA regardless of password guessing."
        else if (s.correctGuessIndex == null)
            "RESULT: the real password is not in the attacker's list — guessing fails."
        else
            "RESULT: a block is hit (at $reachable) before the correct password (position ${s.correctGuessIndex}) — guessing fails."

        if (!s.mfaEnabled) defense += "Enabling MFA would stop this attack outright."

        return Outcome(wouldSucceed, reachable, effectiveRate, minutesToExhaust, stoppedBy, narrative, defense)
    }
}

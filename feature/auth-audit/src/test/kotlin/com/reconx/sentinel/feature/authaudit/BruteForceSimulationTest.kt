package com.reconx.sentinel.feature.authaudit

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class BruteForceSimulationTest {
    private fun base() = BruteForceSimulation.Scenario(
        candidatePasswords = 10000, guessesPerMinute = 60, lockoutThreshold = null,
        lockoutMinutes = 15, rateLimitPerMinute = null, mfaEnabled = false, correctGuessIndex = 100)

    @Test fun `no defenses and password in list succeeds`() {
        val o = BruteForceSimulation.run(base())
        assertThat(o.wouldSucceed).isTrue()
    }
    @Test fun `lockout before the hit stops the attack`() {
        val o = BruteForceSimulation.run(base().copy(lockoutThreshold = 5))
        assertThat(o.wouldSucceed).isFalse()
        assertThat(o.attemptsBeforeBlocked).isEqualTo(5)
    }
    @Test fun `mfa blocks regardless`() {
        val o = BruteForceSimulation.run(base().copy(mfaEnabled = true))
        assertThat(o.wouldSucceed).isFalse()
        assertThat(o.stoppedBy).contains("MFA")
    }
    @Test fun `password not in list fails`() {
        val o = BruteForceSimulation.run(base().copy(correctGuessIndex = null))
        assertThat(o.wouldSucceed).isFalse()
    }
}

package com.reconx.sentinel

import com.google.common.truth.Truth.assertThat
import com.reconx.sentinel.ui.EngagementState
import org.junit.Test

class EngagementStateTest {
    @Test fun `policy maps scope fields`() {
        val e = EngagementState(
            name = "Lab", domains = listOf("example.com"),
            cidrs = listOf("203.0.113.0/24"), exclusions = listOf("secret.example.com"),
            labConfirmed = true)
        val p = e.policy()
        assertThat(p.domains).contains("example.com")
        assertThat(p.cidrs).contains("203.0.113.0/24")
        assertThat(p.exclusions).contains("secret.example.com")
        assertThat(p.allowPrivateForLab).isTrue()
        assertThat(e.hasScope).isTrue()
    }
    @Test fun `no scope means locked`() {
        assertThat(EngagementState().hasScope).isFalse()
    }
}

package com.reconx.sentinel.feature.authaudit

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class AuthAuditTest {
    @Test fun `weak policy produces high severity findings`() {
        val f = PasswordPolicyAuditor.audit("mock-login",
            PasswordPolicy(6, requiresMfa = false, lockoutThreshold = null,
                rateLimited = false, maxAgeDays = 30, blocksBreachedPasswords = false))
        assertThat(f.any { it.title.contains("length") }).isTrue()
        assertThat(f.any { it.title.contains("MFA") }).isTrue()
        assertThat(f.any { it.severity.name == "HIGH" }).isTrue()
    }
    @Test fun `strong policy is clean`() {
        val f = PasswordPolicyAuditor.audit("mock-login",
            PasswordPolicy(14, requiresMfa = true, lockoutThreshold = 5,
                rateLimited = true, maxAgeDays = null, blocksBreachedPasswords = true))
        assertThat(f).isEmpty()
    }
    @Test fun `test plan blocks without authorization`() {
        val plan = AuthTestPlan("prod.example.com", isLocalOrAuthorizedTestEnv = false,
            authorizationProfileId = null)
        assertThat(plan.permitted).isFalse()
        assertThat(plan.blockingReasons()).isNotEmpty()
    }
    @Test fun `test plan permitted for local authorized env`() {
        val plan = AuthTestPlan("127.0.0.1:8080", isLocalOrAuthorizedTestEnv = true,
            authorizationProfileId = "AUTH-123")
        assertThat(plan.permitted).isTrue()
    }
    @Test fun `policy caps are enforced`() {
        try { TestAccountPolicy(maxAttempts = 100); assert(false) }
        catch (e: IllegalArgumentException) { assertThat(e.message).contains("maxAttempts") }
    }
}

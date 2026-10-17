package com.reconx.sentinel.core.security

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class AuthorizationServiceTest {
    private val svc = AuthorizationService()
    private fun req(
        cls: ModuleClass = ModuleClass.ACTIVE,
        status: EngagementStatus = EngagementStatus.APPROVED,
        perm: Boolean = true,
        permitted: Boolean = true,
    ) = AuthorizationService.Request(
        moduleId = "network.service_inventory", moduleClass = cls,
        engagementStatus = status, hasPermission = perm,
        permittedModules = if (permitted) setOf("network.service_inventory") else emptySet(),
    )

    @Test fun `approved active module authorized`() {
        assertThat(svc.authorize(req()).authorized).isTrue()
    }
    @Test fun `active module on non-approved engagement denied`() {
        assertThat(svc.authorize(req(status = EngagementStatus.DRAFT)).authorized).isFalse()
    }
    @Test fun `missing permission denied`() {
        assertThat(svc.authorize(req(perm = false)).authorized).isFalse()
    }
    @Test fun `module not permitted denied`() {
        assertThat(svc.authorize(req(permitted = false)).authorized).isFalse()
    }
    @Test fun `passive module allowed on draft`() {
        assertThat(svc.authorize(req(cls = ModuleClass.PASSIVE,
            status = EngagementStatus.DRAFT)).authorized).isTrue()
    }
    @Test fun `lab module needs confirmation`() {
        val r = req().copy(requiresLabConfirmation = true, labConfirmed = false)
        assertThat(svc.authorize(r).authorized).isFalse()
        assertThat(svc.authorize(r.copy(labConfirmed = true)).authorized).isTrue()
    }
}

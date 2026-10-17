package com.reconx.sentinel.core.security

/** Engagement lifecycle gate: active modules require an APPROVED engagement. */
enum class EngagementStatus { DRAFT, PENDING_APPROVAL, APPROVED, CLOSED }

enum class ModuleClass { PASSIVE, ACTIVE }

/**
 * Central authorization check every active engine must call before it runs,
 * matching the backend gates (RBAC + engagement approval + scope). This is the
 * single chokepoint required by spec §13/§17 ("All active assessment modules
 * must use the same authorization and scope-validation service").
 */
class AuthorizationService {
    data class Request(
        val moduleId: String,
        val moduleClass: ModuleClass,
        val engagementStatus: EngagementStatus,
        val permittedModules: Set<String>,
        val hasPermission: Boolean,
        val labConfirmed: Boolean = false,
        val requiresLabConfirmation: Boolean = false,
    )

    data class Verdict(val authorized: Boolean, val reason: String)

    fun authorize(req: Request): Verdict {
        if (!req.hasPermission)
            return Verdict(false, "operator role lacks permission for ${req.moduleId}")
        if (req.moduleId !in req.permittedModules)
            return Verdict(false, "module ${req.moduleId} is not permitted for this engagement")
        if (req.moduleClass == ModuleClass.ACTIVE &&
            req.engagementStatus != EngagementStatus.APPROVED)
            return Verdict(false, "active modules require an approved engagement")
        if (req.requiresLabConfirmation && !req.labConfirmed)
            return Verdict(false, "lab module requires explicit lab confirmation")
        return Verdict(true, "authorized")
    }
}

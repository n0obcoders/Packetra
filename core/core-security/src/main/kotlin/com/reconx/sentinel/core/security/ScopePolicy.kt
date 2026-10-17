package com.reconx.sentinel.core.security

/**
 * The authorized boundary of an engagement. Deny-by-default: a target is only
 * in scope if it matches an include rule AND matches no exclusion AND is not
 * caught by the hard safety blocks. Mirrors the ReconX scope firewall so that
 * on-device engines enforce the same contract as the backend (spec §13, §17).
 */
data class ScopePolicy(
    val version: Int,
    /** Authorized domains (suffix match, e.g. "example.com" covers "a.example.com"). */
    val domains: Set<String> = emptySet(),
    /** Authorized IP ranges in CIDR notation. */
    val cidrs: List<String> = emptyList(),
    /** Explicitly excluded hosts/domains/IPs (take precedence over includes). */
    val exclusions: Set<String> = emptySet(),
    /** Hard safety: refuse RFC1918 / loopback / link-local unless a lab opt-in is set. */
    val blockPrivateNetworks: Boolean = true,
    /** Hard safety: always refuse cloud metadata endpoints (169.254.169.254, etc.). */
    val blockMetadataEndpoints: Boolean = true,
    /** Lab opt-in: allow private ranges ONLY for an explicitly-confirmed lab engagement. */
    val allowPrivateForLab: Boolean = false,
)

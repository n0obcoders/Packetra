package com.reconx.sentinel.core.security

import java.net.InetAddress

/**
 * Validates a target (hostname or IP literal) against a [ScopePolicy].
 *
 * Safety contract (deny-by-default), checked in order:
 *  1. Metadata endpoints are ALWAYS denied when blockMetadataEndpoints is set.
 *  2. Private/loopback/link-local addresses are denied unless an explicit lab
 *     opt-in (allowPrivateForLab) is set.
 *  3. Explicit exclusions are denied.
 *  4. A target must match an include rule (domain suffix or CIDR) to be allowed.
 *
 * DNS resolution is injectable so this class stays unit-testable and so demo
 * mode can supply a synthetic resolver (no outbound traffic), exactly like the
 * ReconX backend.
 */
class ScopeValidator(
    private val policy: ScopePolicy,
    private val resolver: (String) -> List<InetAddress> = { host ->
        runCatching { InetAddress.getAllByName(host).toList() }.getOrDefault(emptyList())
    },
) {
    private val cidrRules: List<Pair<String, Cidr>> =
        policy.cidrs.mapNotNull { spec -> Cidr.parseOrNull(spec)?.let { spec to it } }
    private val exclusionCidrs: List<Cidr> =
        policy.exclusions.mapNotNull { Cidr.parseOrNull(it) }

    fun validate(target: String): ScopeDecision {
        val host = normalize(target)
        if (host.isEmpty()) return ScopeDecision.deny(target, "empty target")

        // Collect candidate IPs: the literal itself if it is one, else resolved.
        val literal = runCatching { InetAddress.getByName(host) }
            .getOrNull()?.takeIf { isIpLiteral(host) }
        val addrs: List<InetAddress> = if (literal != null) listOf(literal) else resolver(host)

        // 1. Metadata endpoints — always blocked.
        if (policy.blockMetadataEndpoints) {
            if (host in METADATA_HOSTS || addrs.any { it.hostAddress in METADATA_IPS }) {
                return ScopeDecision.deny(target, "cloud metadata endpoint is never in scope")
            }
        }
        // 2. Private / loopback / link-local.
        if (policy.blockPrivateNetworks && !policy.allowPrivateForLab) {
            val priv = addrs.firstOrNull { it.isPrivate() }
            if (priv != null) {
                return ScopeDecision.deny(
                    target, "private/loopback address ${priv.hostAddress} blocked " +
                        "(enable a confirmed lab engagement to allow)"
                )
            }
        }
        // 3. Exclusions win.
        matchExclusion(host, addrs)?.let {
            return ScopeDecision.deny(target, "explicitly excluded by rule '$it'")
        }
        // 4. Must match an include rule.
        matchDomain(host)?.let { return ScopeDecision.allow(target, "domain:$it") }
        matchCidr(addrs)?.let { return ScopeDecision.allow(target, "cidr:$it") }

        return ScopeDecision.deny(target, "no authorized scope rule matches this target")
    }

    fun validateAll(targets: List<String>): List<ScopeDecision> = targets.map(::validate)
    fun allowed(targets: List<String>): List<String> =
        validateAll(targets).filter { it.allowed }.map { it.target }

    private fun matchDomain(host: String): String? {
        if (isIpLiteral(host)) return null
        return policy.domains.firstOrNull { d ->
            val dd = d.lowercase().trimStart('.')
            host == dd || host.endsWith(".$dd")
        }
    }

    private fun matchCidr(addrs: List<InetAddress>): String? =
        cidrRules.firstOrNull { (_, c) -> addrs.any { c.contains(it) } }?.first

    private fun matchExclusion(host: String, addrs: List<InetAddress>): String? {
        policy.exclusions.firstOrNull { ex ->
            val e = ex.lowercase().trimStart('.')
            !e.contains('/') && (host == e || host.endsWith(".$e"))
        }?.let { return it }
        return exclusionCidrs.firstOrNull { c -> addrs.any { c.contains(it) } }
            ?.let { c -> policy.exclusions.first { Cidr.parseOrNull(it) == c } }
    }

    private fun normalize(t: String): String =
        t.trim().lowercase().substringAfter("://").substringBefore('/').substringBefore(':')

    private fun isIpLiteral(h: String): Boolean =
        h.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) || h.contains(':')

    companion object {
        private val METADATA_IPS = setOf("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
        private val METADATA_HOSTS = setOf("metadata.google.internal")
    }
}

private fun InetAddress.isPrivate(): Boolean =
    isLoopbackAddress || isLinkLocalAddress || isSiteLocalAddress || isAnyLocalAddress

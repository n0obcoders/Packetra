package com.reconx.sentinel.feature.recon

import com.reconx.sentinel.core.common.DispatcherProvider
import java.net.InetAddress
import kotlinx.coroutines.withContext

/**
 * Confirms whether a discovered subdomain actually resolves. Resolution is a
 * DNS lookup only — it is passive (the query goes to a resolver, not to the
 * target's own services), so it is not gated by scope. Scope is still enforced
 * separately before any ACTIVE probe (port scan, HTTP request) of a confirmed
 * host, by the engines that perform those probes (spec §7).
 */
class DnsValidator(
    private val dispatchers: DispatcherProvider,
    private val resolver: (String) -> List<InetAddress> = { host ->
        runCatching { InetAddress.getAllByName(host).toList() }.getOrDefault(emptyList())
    },
) {
    suspend fun confirm(sub: Subdomain): Subdomain = withContext(dispatchers.io) {
        val addrs = resolver(sub.name)
        sub.copy(
            resolved = addrs.isNotEmpty(),
            addresses = addrs.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() },
            source = if (sub.source.contains("dns")) sub.source else "${sub.source}+dns",
        )
    }

    suspend fun confirmAll(subs: List<Subdomain>): List<Subdomain> = subs.map { confirm(it) }
}

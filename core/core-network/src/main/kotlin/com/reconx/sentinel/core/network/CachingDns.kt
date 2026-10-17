package com.reconx.sentinel.core.network

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import okhttp3.Dns

/**
 * A process-wide DNS cache for OkHttp. Repeated assessment requests to the same
 * host (directory brute-forcing, multi-record recon, many probes) otherwise
 * re-resolve the name on every call; this caches positive lookups for a bounded
 * TTL so the resolver is hit once per host per window. Failures are not cached,
 * so a transient resolver error does not poison the host. Thread-safe.
 */
class CachingDns(
    private val ttlMillis: Long = 5 * 60_000L,
    private val maxEntries: Int = 2048,
    private val delegate: Dns = Dns.SYSTEM,
    private val clock: () -> Long = System::currentTimeMillis,
) : Dns {
    private data class Entry(val addrs: List<InetAddress>, val expiresAt: Long)
    private val cache = ConcurrentHashMap<String, Entry>()

    override fun lookup(hostname: String): List<InetAddress> {
        val now = clock()
        cache[hostname]?.let { if (it.expiresAt > now) return it.addrs else cache.remove(hostname) }
        val resolved = delegate.lookup(hostname) // throws UnknownHostException on failure (not cached)
        if (cache.size >= maxEntries) cache.clear()
        cache[hostname] = Entry(resolved, now + ttlMillis)
        return resolved
    }

    fun clear() = cache.clear()
    fun size(): Int = cache.size
}

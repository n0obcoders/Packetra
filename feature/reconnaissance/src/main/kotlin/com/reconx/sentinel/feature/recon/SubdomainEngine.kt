package com.reconx.sentinel.feature.recon

import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.network.HttpClients
import java.net.InetAddress
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Sublist3r-style passive subdomain discovery. Queries several public OSINT
 * sources concurrently (never the target itself), merges with per-host source
 * attribution, detects wildcard DNS, and optionally confirms each name with a
 * DNS lookup. Failed/unavailable sources are reported, never hidden, and nothing
 * is fabricated.
 */
class SubdomainEngine(
    private val dispatchers: DispatcherProvider,
    private val client: OkHttpClient = HttpClients.osint(),
) {
    data class SourceStatus(val name: String, val found: Int, val error: String? = null)
    data class Sub(val host: String, val sources: MutableSet<String>,
                   var resolved: Boolean = false, var addresses: List<String> = emptyList())
    data class Result(val domain: String, val subs: List<Sub>, val sources: List<SourceStatus>,
                      val wildcard: Boolean)

    suspend fun discover(domain: String, validate: Boolean): Result = coroutineScope {
        val d = domain.trim().lowercase().removePrefix("*.")
        val jobs = listOf(
            async(dispatchers.io) { crtSh(d) },
            async(dispatchers.io) { hackerTarget(d) },
            async(dispatchers.io) { certSpotter(d) },
            async(dispatchers.io) { otx(d) },
            async(dispatchers.io) { rapidDns(d) },
            async(dispatchers.io) { urlscan(d) },
            async(dispatchers.io) { wayback(d) },
            async(dispatchers.io) { subdomainCenter(d) },
        )
        val outcomes = jobs.awaitAll()
        val merged = LinkedHashMap<String, Sub>()
        val statuses = mutableListOf<SourceStatus>()
        for ((name, names, err) in outcomes) {
            statuses += SourceStatus(name, names.size, err)
            for (h in names) merged.getOrPut(h) { Sub(h, mutableSetOf()) }.sources.add(name)
        }
        val wildcard = withContext(dispatchers.io) { detectWildcard(d) }
        if (validate) {
            val subs = merged.values.toList()
            val checked = subs.map { async(dispatchers.io) {
                val addrs = runCatching { InetAddress.getAllByName(it.host).map { a -> a.hostAddress ?: "" } }
                    .getOrDefault(emptyList()).filter { s -> s.isNotEmpty() }
                it.resolved = addrs.isNotEmpty(); it.addresses = addrs; it
            } }.awaitAll()
            Result(d, checked.sortedBy { it.host }, statuses, wildcard)
        } else {
            Result(d, merged.values.sortedBy { it.host }, statuses, wildcard)
        }
    }

    private data class SrcOut(val name: String, val names: Set<String>, val error: String?)
    private data class Fetched(val body: String?, val error: String?)

    /** Fetches a URL, retrying once on timeout or 5xx. Returns the body, or a
     *  specific error string (HTTP code / exception) instead of a generic one. */
    private fun fetch(url: String, retries: Int = 1): Fetched {
        var lastErr: String? = null
        repeat(retries + 1) { attempt ->
            val result = runCatching {
                client.newCall(Request.Builder().url(url)
                    .header("User-Agent", HttpClients.USER_AGENT)
                    .header("Accept", "application/json, text/plain, */*").build()).execute().use { r ->
                    when {
                        r.isSuccessful -> Fetched(r.body?.string(), null)
                        r.code >= 500 || r.code == 429 ->
                            Fetched(null, if (r.code == 429) "rate-limited (HTTP 429)" else "HTTP ${r.code}") // retryable
                        else -> return Fetched(null, "HTTP ${r.code}")      // not retryable
                    }
                }
            }.getOrElse { Fetched(null, it.message ?: it.javaClass.simpleName) }
            if (result.body != null) return result
            lastErr = result.error
            // brief backoff before retry
            if (attempt < retries) Thread.sleep(400L * (attempt + 1))
        }
        return Fetched(null, lastErr ?: "unavailable")
    }

    private fun extract(body: String?, domain: String): Set<String> {
        if (body == null) return emptySet()
        val rx = Regex("""[a-z0-9_*][a-z0-9._-]*\.${Regex.escape(domain)}""", RegexOption.IGNORE_CASE)
        return rx.findAll(body).map { it.value.lowercase().removePrefix("*.") }
            .filter { it.endsWith(".$domain") || it == domain }.toSortedSet()
    }

    private fun crtSh(d: String): SrcOut {
        // crt.sh is slow and occasionally 5xx; fetch() already retries those.
        val f = fetch("https://crt.sh/?q=%25.$d&output=json", retries = 2)
        return SrcOut("crt.sh", extract(f.body, d), f.error)
    }
    private fun hackerTarget(d: String): SrcOut {
        val f = fetch("https://api.hackertarget.com/hostsearch/?q=$d")
        val err = when {
            f.body == null -> f.error
            f.body.contains("API count exceeded") -> "rate-limited"
            else -> null
        }
        return SrcOut("hackertarget", extract(f.body, d), err)
    }
    private fun certSpotter(d: String): SrcOut {
        val f = fetch("https://api.certspotter.com/v1/issuances?domain=$d&include_subdomains=true&expand=dns_names")
        return SrcOut("certspotter", extract(f.body, d), f.error)
    }
    private fun otx(d: String): SrcOut {
        // OTX rate-limits by source IP; retry eases transient 429s (the shared
        // outbound IP of a build server hits them more than a phone will).
        val f = fetch("https://otx.alienvault.com/api/v1/indicators/domain/$d/passive_dns", retries = 2)
        return SrcOut("otx", extract(f.body, d), f.error)
    }
    private fun rapidDns(d: String): SrcOut {
        val f = fetch("https://rapiddns.io/subdomain/$d?full=1")
        return SrcOut("rapiddns", extract(f.body, d), f.error)
    }
    private fun urlscan(d: String): SrcOut {
        // urlscan.io public search: keyless, reliable; extract page domains.
        val f = fetch("https://urlscan.io/api/v1/search/?q=domain:$d&size=1000")
        return SrcOut("urlscan", extract(f.body, d), f.error)
    }
    private fun wayback(d: String): SrcOut {
        // Wayback CDX: historical URLs for the domain; extract hostnames. MUST be
        // https — Android's network-security config blocks cleartext http, which
        // is why this source previously failed with a "cleartext not permitted".
        val f = fetch("https://web.archive.org/cdx/search/cdx?url=*.$d&output=text&fl=original&collapse=urlkey&limit=5000")
        return SrcOut("wayback", extract(f.body, d), f.error)
    }
    private fun subdomainCenter(d: String): SrcOut {
        // subdomain.center: keyless JSON array of subdomains; reliable and often
        // broader than CT-only sources.
        val f = fetch("https://api.subdomain.center/?domain=$d", retries = 1)
        return SrcOut("subdomain.center", extract(f.body, d), f.error)
    }

    /** A wildcard zone resolves a random label; discovery results then need care. */
    private fun detectWildcard(d: String): Boolean {
        val rnd = "zz" + System.nanoTime().toString(36) + ".$d"
        return runCatching { InetAddress.getAllByName(rnd).isNotEmpty() }.getOrDefault(false)
    }
}

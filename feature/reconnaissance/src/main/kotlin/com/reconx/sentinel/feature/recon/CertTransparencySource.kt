package com.reconx.sentinel.feature.recon

import com.reconx.sentinel.core.common.Outcome
import com.reconx.sentinel.core.network.HttpClients
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Passive subdomain discovery from Certificate Transparency logs via the public
 * crt.sh JSON endpoint (spec §7). PASSIVE: it queries a public CT aggregator and
 * never touches the target domain's infrastructure. Results are unverified until
 * [DnsValidator] confirms them, and every entry keeps its source attribution.
 *
 * The CT endpoint is configurable; an operator can point at their own log mirror.
 */
class CertTransparencySource(
    private val client: OkHttpClient = HttpClients.assessment(followRedirects = true),
    private val endpoint: String = "https://crt.sh",
) {
    private val listType = Types.newParameterizedType(List::class.java, CrtEntry::class.java)
    private val adapter = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
        .adapter<List<CrtEntry>>(listType)

    data class CrtEntry(val name_value: String?)

    suspend fun discover(domain: String): Outcome<List<Subdomain>> {
        val url = "$endpoint/?q=%25.${domain.trim().lowercase()}&output=json"
        val req = Request.Builder().url(url)
            .header("User-Agent", HttpClients.USER_AGENT).build()
        return try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return Outcome.Err("crt.sh HTTP ${resp.code}")
                val body = resp.body?.string().orEmpty()
                val entries = adapter.fromJson(body) ?: emptyList()
                val names = entries
                    .flatMap { (it.name_value ?: "").split('\n') }
                    .map { it.trim().lowercase().removePrefix("*.") }
                    .filter { it.endsWith(".$domain") || it == domain }
                    .toSortedSet()
                Outcome.Ok(names.map { Subdomain(it, source = "crt.sh") })
            }
        } catch (t: Throwable) {
            Outcome.Err("CT discovery failed: ${t.message}", t)
        }
    }
}

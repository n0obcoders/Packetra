package com.reconx.sentinel.feature.recon

import com.reconx.sentinel.core.common.Outcome
import com.reconx.sentinel.core.network.HttpClients
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * DNS-over-HTTPS resolver (RFC 8484 JSON form) against a public resolver. This
 * is PASSIVE from the target's point of view — the query goes to the DoH
 * provider, not to the target's own nameservers — and it unlocks record types
 * (MX/NS/TXT/CAA/SOA/CNAME) that Android's InetAddress cannot return. The
 * provider is configurable; an operator can point at their own DoH endpoint.
 */
class DohResolver(
    private val client: OkHttpClient = HttpClients.assessment(followRedirects = true),
    private val endpoint: String = "https://dns.google/resolve",
) {
    @JsonClass(generateAdapter = true)
    data class DohAnswer(val name: String?, val type: Int?, val TTL: Int?, val data: String?)

    @JsonClass(generateAdapter = true)
    data class DohResponse(val Status: Int?, val AD: Boolean?, val Answer: List<DohAnswer>?)

    private val adapter = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
        .adapter(DohResponse::class.java)

    data class Record(val type: String, val value: String, val ttl: Int?)
    data class ZoneView(val records: List<Record>, val dnssec: Boolean)

    suspend fun query(name: String, type: String): Outcome<DohResponse> = withContext(Dispatchers.IO) {
        // Always run the blocking OkHttp call off the caller's thread. Callers such
        // as the web-assessment email check invoke this from viewModelScope (Main),
        // and a bare execute() there throws NetworkOnMainThreadException and crashes
        // the app — this withContext makes the resolver safe from any dispatcher.
        val url = "$endpoint?name=${name.trim().lowercase()}&type=$type"
        val req = Request.Builder().url(url)
            .header("Accept", "application/dns-json")
            .header("User-Agent", HttpClients.USER_AGENT).build()
        try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@withContext Outcome.Err("DoH HTTP ${resp.code}")
                val parsed = adapter.fromJson(resp.body?.string().orEmpty())
                    ?: return@withContext Outcome.Err("DoH: empty response")
                Outcome.Ok(parsed)
            }
        } catch (t: Throwable) { Outcome.Err("DoH query failed: ${t.message}", t) }
    }

    /** Inventories the common record types for a domain in one pass. */
    suspend fun inventory(domain: String): Outcome<ZoneView> {
        val types = listOf("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
        val records = mutableListOf<Record>()
        var dnssec = false
        for (t in types) {
            when (val r = query(domain, t)) {
                is Outcome.Ok -> {
                    if (r.value.AD == true) dnssec = true
                    r.value.Answer.orEmpty().forEach { a ->
                        a.data?.let { records.add(Record(typeName(a.type), it.trim('"'), a.TTL)) }
                    }
                }
                is Outcome.Err -> if (t == "A") return Outcome.Err(r.message)  // first query failing = network problem
            }
        }
        return Outcome.Ok(ZoneView(records.distinct(), dnssec))
    }

    private fun typeName(t: Int?): String = when (t) {
        1 -> "A"; 28 -> "AAAA"; 5 -> "CNAME"; 15 -> "MX"; 2 -> "NS"
        16 -> "TXT"; 257 -> "CAA"; 6 -> "SOA"; 33 -> "SRV"; else -> "T$t"
    }
}

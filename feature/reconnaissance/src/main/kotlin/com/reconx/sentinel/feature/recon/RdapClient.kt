package com.reconx.sentinel.feature.recon

import com.reconx.sentinel.core.common.Outcome
import com.reconx.sentinel.core.network.HttpClients
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Registrar/ownership lookup over RDAP (RFC 9083) — the modern, JSON replacement
 * for WHOIS. Queries the public bootstrap resolver at rdap.org, which redirects
 * to the authoritative registry. Fully passive (it asks a registry database, not
 * the target), keyless, and read-only. Parsing is pure/testable; only [lookup]
 * touches the network.
 */
class RdapClient(
    private val client: OkHttpClient = HttpClients.osint(),
    private val endpoint: String = "https://rdap.org/domain",
) {
    data class Whois(
        val domain: String,
        val registrar: String?,
        val registered: String?,
        val expires: String?,
        val lastChanged: String?,
        val statuses: List<String>,
        val nameservers: List<String>,
    )

    suspend fun lookup(domain: String): Outcome<Whois> = withContext(Dispatchers.IO) {
        val d = domain.trim().lowercase().removePrefix("*.")
        val req = Request.Builder().url("$endpoint/$d")
            .header("Accept", "application/rdap+json")
            .header("User-Agent", HttpClients.USER_AGENT).build()
        try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@withContext Outcome.Err("RDAP HTTP ${resp.code}")
                val body = resp.body?.string().orEmpty()
                if (body.isBlank()) return@withContext Outcome.Err("RDAP: empty response")
                Outcome.Ok(parse(body, d))
            }
        } catch (t: Throwable) { Outcome.Err("RDAP lookup failed: ${t.message}", t) }
    }

    companion object {
        private fun event(json: String, action: String): String? =
            Regex(""""eventAction"\s*:\s*"$action"\s*,\s*"eventDate"\s*:\s*"([^"]+)"""")
                .find(json)?.groupValues?.get(1)
                ?: Regex(""""eventDate"\s*:\s*"([^"]+)"\s*,\s*"eventAction"\s*:\s*"$action"""")
                    .find(json)?.groupValues?.get(1)

        /** Pure parse of an RDAP JSON document into the fields we surface. */
        fun parse(json: String, domain: String): Whois {
            val registrar = Regex(
                """"roles"\s*:\s*\[\s*"registrar"\s*\][\s\S]{0,500}?"fn"\s*,\s*\{[^}]*\}\s*,\s*"text"\s*,\s*"([^"]+)""""
            ).find(json)?.groupValues?.get(1)

            val statuses = Regex(""""status"\s*:\s*\[([^\]]*)\]""").find(json)?.groupValues?.get(1)
                ?.let { seg -> Regex(""""([^"]+)"""").findAll(seg).map { it.groupValues[1] }.toList() }
                .orEmpty()

            val nsSegment = Regex(""""nameservers"\s*:\s*\[([\s\S]*?)\]\s*(?:,\s*"|\})""").find(json)?.groupValues?.get(1)
            val nameservers = nsSegment?.let {
                Regex(""""ldhName"\s*:\s*"([^"]+)"""").findAll(it).map { m -> m.groupValues[1].lowercase() }.toList()
            }.orEmpty().distinct()

            return Whois(
                domain = domain,
                registrar = registrar,
                registered = event(json, "registration"),
                expires = event(json, "expiration"),
                lastChanged = event(json, "last changed"),
                statuses = statuses,
                nameservers = nameservers,
            )
        }
    }
}

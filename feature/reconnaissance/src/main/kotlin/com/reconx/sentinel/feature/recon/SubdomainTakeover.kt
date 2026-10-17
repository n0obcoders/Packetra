package com.reconx.sentinel.feature.recon

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification
import com.reconx.sentinel.core.network.HttpClients
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Subdomain-takeover detection. For each discovered host it resolves the CNAME
 * (passively, over DoH), and if that CNAME points at a known third-party service
 * it fetches the host once (GET, follow redirects) and checks the response for
 * the service's own "unclaimed resource" banner. A match = a dangling pointer an
 * attacker could claim, raised as a CRITICAL finding.
 *
 * Strictly a DETECTOR: it never registers, claims or alters the resource. Work is
 * bounded (host cap + concurrency limit) and GET-only.
 */
class SubdomainTakeover(
    private val dispatchers: DispatcherProvider,
    private val doh: DohResolver = DohResolver(),
    private val client: OkHttpClient = HttpClients.assessment(followRedirects = true),
) {
    data class Result(val host: String, val cname: String, val service: String,
                      val vulnerable: Boolean, val evidence: String)

    private val sem = Semaphore(6)

    /** Checks up to [max] hosts; returns findings (CRITICAL for confirmed dangling pointers). */
    suspend fun check(hosts: List<String>, max: Int = 40): List<Finding> = withContext(dispatchers.io) {
        val results = coroutineScope {
            hosts.distinct().take(max).map { h ->
                async { sem.withPermit { inspect(h) } }
            }.awaitAll()
        }.filterNotNull()
        results.map { toFinding(it) }
    }

    private suspend fun inspect(host: String): Result? {
        val cname = resolveCname(host) ?: return null
        val svc = TakeoverRules.serviceForCname(cname) ?: return null
        // The CNAME delegates to a known service; fetch once to see if it is unclaimed.
        val body = fetchBody(host) ?: ""
        val vulnerable = TakeoverRules.hasDanglingFingerprint(svc, body)
        return Result(host, cname, svc.service, vulnerable,
            if (vulnerable) "Service banner for an unclaimed ${svc.service} resource was served."
            else "CNAME delegates to ${svc.service}; no clear dangling banner (verify the resource is claimed).")
    }

    private suspend fun resolveCname(host: String): String? {
        val r = doh.query(host, "CNAME")
        val ans = (r as? com.reconx.sentinel.core.common.Outcome.Ok)?.value?.Answer.orEmpty()
        return ans.firstOrNull { it.type == 5 }?.data?.trim()?.trimEnd('.')
            ?: ans.firstOrNull()?.data?.trim()?.trimEnd('.')
    }

    private fun fetchBody(host: String): String? {
        for (scheme in listOf("https://", "http://")) {
            val body = runCatching {
                client.newCall(Request.Builder().url("$scheme$host")
                    .header("User-Agent", HttpClients.USER_AGENT).get().build()).execute().use {
                    it.body?.source()?.peek()?.readByteString(65536L)?.utf8() ?: ""
                }
            }.getOrNull()
            if (body != null) return body
        }
        return null
    }

    private fun toFinding(r: Result): Finding = Finding(
        id = "takeover-${r.host.hashCode().toUInt().toString(16)}",
        title = if (r.vulnerable) "Potential subdomain takeover: ${r.host} (${r.service})"
                else "Subdomain delegates to ${r.service}: ${r.host}",
        category = "subdomain_takeover",
        severity = if (r.vulnerable) Severity.HIGH else Severity.LOW,
        confidence = if (r.vulnerable) Confidence.FIRM else Confidence.TENTATIVE,
        target = r.host,
        evidence = mapOf("cname" to r.cname, "service" to r.service),
        explanation = if (r.vulnerable)
            "${r.host} has a CNAME to ${r.service} (${r.cname}) and that service is serving its 'unclaimed resource' " +
                "page — the pointer is dangling, so anyone who registers it on ${r.service} can serve content from this " +
                "subdomain (cookie theft, phishing, CSP bypass). " + r.evidence
        else "${r.host} delegates to ${r.service} via CNAME (${r.cname}). " + r.evidence,
        remediation = if (r.vulnerable)
            "Remove or re-point the dangling DNS record immediately, or re-claim the resource on ${r.service}."
        else "Confirm the ${r.service} resource is still owned by you; remove the record if not.",
        verification = Verification.VALIDATED_SAFELY, source = "reconnaissance")
}

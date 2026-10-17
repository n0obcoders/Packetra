package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Outcome
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification
import com.reconx.sentinel.core.network.HttpClients
import com.reconx.sentinel.core.security.ScopeValidator
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.TlsVersion
import com.reconx.sentinel.core.common.DispatcherProvider
import kotlinx.coroutines.withContext

/**
 * Non-destructive web security assessment. One GET per hop; redirects are
 * followed MANUALLY and each hop is scope-validated, so an in-scope URL can
 * never bounce the assessor to an out-of-scope host (the redirect chain is
 * reported). Reads response headers, cookies, TLS handshake metadata and the
 * page <title>. No fuzzing, no write methods. The previous build only issued a
 * single non-redirect-following GET, which returned an almost-empty 301/302 and
 * looked broken; this follows the chain within scope and always returns a
 * concrete report.
 */
class WebAssessor(
    private val scope: ScopeValidator,
    private val dispatchers: DispatcherProvider,
    private val client: OkHttpClient = HttpClients.assessment(followRedirects = false),
    private val maxRedirects: Int = 5,
) {
    suspend fun assess(url: String): Outcome<WebReport> {
        val first = scope.validate(url)
        if (!first.allowed) return Outcome.Err("refused: ${first.reason}")
        return withContext(dispatchers.io) {
            try { Outcome.Ok(run(url)) }
            catch (t: Throwable) { Outcome.Err("assessment of $url failed: ${t.message}", t) }
        }
    }

    private fun run(startUrl: String): WebReport {
        val chain = mutableListOf<String>()
        val notes = mutableListOf<String>()
        var current: String
        var hops = 0
        var finalHeaders: Map<String, String> = emptyMap()
        var finalHttps = false
        var finalStatus = 0
        var finalStatusLine = ""
        var server: String? = null
        var tls: TlsInfo? = null
        var title: String? = null

        var redirectTo: String? = startUrl
        while (redirectTo != null) {
            current = redirectTo!!
            redirectTo = null
            val decision = scope.validate(current)
            if (!decision.allowed) { notes += "redirect to out-of-scope $current — not followed"; break }
            chain += current
            val req = Request.Builder().url(current).get()
                .header("User-Agent", HttpClients.USER_AGENT).build()
            client.newCall(req).execute().use { resp ->
                finalStatus = resp.code
                finalStatusLine = "${resp.code} ${resp.message}"
                finalHeaders = resp.headers.names().associateWith { resp.headers(it).joinToString("; ") }
                finalHttps = resp.request.url.isHttps
                server = resp.header("Server")
                tls = resp.handshake?.let { hs ->
                    val cert = hs.peerCertificates.firstOrNull() as? java.security.cert.X509Certificate
                    val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
                    val days = cert?.notAfter?.let {
                        TimeUnit.MILLISECONDS.toDays(it.time - System.currentTimeMillis())
                    }
                    val sans = runCatching {
                        cert?.subjectAlternativeNames?.mapNotNull { entry ->
                            // entry[0]==2 => dNSName; entry[1] is the value
                            (entry.getOrNull(1) as? String)?.trim()
                        }?.filter { it.isNotEmpty() }?.distinct().orEmpty()
                    }.getOrDefault(emptyList())
                    TlsInfo(
                        version = hs.tlsVersion.javaName,
                        cipher = hs.cipherSuite.javaName,
                        subject = cert?.subjectX500Principal?.name,
                        issuer = cert?.issuerX500Principal?.name,
                        notAfter = cert?.notAfter?.let { fmt.format(it) },
                        daysToExpiry = days,
                        sans = sans,
                    )
                }
                val location = resp.header("Location")
                if (resp.isRedirect && location != null && hops < maxRedirects) {
                    hops++
                    redirectTo = resp.request.url.resolve(location)?.toString() ?: location
                } else {
                    title = resp.body?.let { b ->
                        val slice = b.source().peek().readByteString(65536L).utf8()
                        Regex("(?is)<title[^>]*>(.*?)</title>").find(slice)?.groupValues?.get(1)?.trim()?.take(160)
                    }
                }
            }
        }

        val finalUrl = chain.lastOrNull() ?: startUrl
        // Legacy TLS 1.0/1.1 support probe on the final HTTPS endpoint.
        if (finalHttps && tls != null) {
            val legacy = probeLegacyTls(finalUrl, notes)
            if (legacy.isNotEmpty()) tls = tls!!.copy(legacyProtocols = legacy)
        }

        val findings = buildFindings(finalUrl, finalHttps, finalHeaders, tls, notes).toMutableList()
        // HTTP→HTTPS redirect-chain validation (passive, over the chain we followed).
        findings += RedirectChainValidator.analyze(finalUrl, chain, finalHttps)
        val passed = PassedChecksAnalyzer.analyze(finalHttps, finalHeaders, tls, chain)
        return WebReport(
            requestedUrl = startUrl, finalUrl = finalUrl,
            status = finalStatus, statusLine = finalStatusLine, server = server,
            https = finalHttps, title = title, redirectChain = chain, tls = tls,
            findings = findings, notes = notes, passedChecks = passed,
        )
    }

    /**
     * Attempts a handshake restricted to TLS 1.0 and (separately) TLS 1.1 to see
     * whether the server still negotiates them. Legacy versions are disabled in
     * modern runtimes, so a negative result can mean "device cannot test" rather
     * than "server refuses"; that caveat is noted, never overstated.
     */
    private fun probeLegacyTls(url: String, notes: MutableList<String>): List<String> {
        val negotiated = mutableListOf<String>()
        var anyTestable = false
        for (v in listOf(TlsVersion.TLS_1_0, TlsVersion.TLS_1_1)) {
            val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(v).build()
            val probe = client.newBuilder()
                .connectionSpecs(listOf(spec))
                .connectTimeout(6, TimeUnit.SECONDS)
                .readTimeout(6, TimeUnit.SECONDS)
                .callTimeout(10, TimeUnit.SECONDS)
                .build()
            val result = runCatching {
                probe.newCall(Request.Builder().url(url).head()
                    .header("User-Agent", HttpClients.USER_AGENT).build()).execute().use { it.handshake?.tlsVersion }
            }
            if (result.isSuccess) {
                anyTestable = true
                if (result.getOrNull() == v) negotiated += v.javaName
            }
        }
        if (!anyTestable) notes += "Legacy TLS 1.0/1.1 could not be tested from this device (the runtime disables them)."
        return negotiated
    }

    private fun buildFindings(
        url: String, https: Boolean, headers: Map<String, String>,
        tls: TlsInfo?, notes: MutableList<String>,
    ): List<Finding> {
        val out = HeaderAnalyzer.analyze(url, https, headers).toMutableList()
        tls?.daysToExpiry?.let { d ->
            if (d in 0..21) out += Finding(
                id = "web-tls-expiry-${url.hashCode().toUInt().toString(16)}",
                title = "TLS certificate expires in $d day(s)", category = "transport_security",
                severity = if (d <= 7) Severity.HIGH else Severity.MEDIUM, confidence = Confidence.CONFIRMED,
                target = url, explanation = "The served certificate expires on ${tls.notAfter}.",
                remediation = "Renew the certificate before expiry and automate renewal.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment",
            )
            if (d < 0) out += Finding(
                id = "web-tls-expired-${url.hashCode().toUInt().toString(16)}",
                title = "TLS certificate is expired", category = "transport_security",
                severity = Severity.HIGH, confidence = Confidence.CONFIRMED, target = url,
                explanation = "The served certificate expired on ${tls.notAfter}.",
                remediation = "Replace the expired certificate immediately.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment",
            )
        }
        // Weak/deprecated negotiated cipher suite.
        tls?.cipher?.let { c -> TlsCipherRules.weakness(c)?.let { why -> out += TlsCipherRules.finding(url, c, why) } }
        // Legacy TLS 1.0/1.1 still negotiated.
        tls?.legacyProtocols?.takeIf { it.isNotEmpty() }?.let { legacy ->
            out += Finding(
                id = "web-tls-legacy-${url.hashCode().toUInt().toString(16)}",
                title = "Legacy TLS supported (${legacy.joinToString(", ")})", category = "transport_security",
                severity = Severity.MEDIUM, confidence = Confidence.CONFIRMED, target = url,
                evidence = mapOf("protocols" to legacy.joinToString(", ")),
                explanation = "The server still negotiates ${legacy.joinToString(" and ")}, which are deprecated " +
                    "(PCI DSS disallows them) and exposed to downgrade and known cipher weaknesses.",
                remediation = "Disable TLS 1.0 and 1.1; serve only TLS 1.2 and 1.3.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment",
            )
        }
        // SANs as a sibling-subdomain telemetry signal (informational, passive).
        tls?.sans?.filter { !it.startsWith("*.") }?.distinct()?.takeIf { it.size > 1 }?.let { sans ->
            out += Finding(
                id = "web-tls-sans-${url.hashCode().toUInt().toString(16)}",
                title = "Certificate lists ${sans.size} subject alternative names", category = "information_disclosure",
                severity = Severity.INFO, confidence = Confidence.CONFIRMED, target = url,
                evidence = mapOf("sans" to sans.joinToString(", ").take(500)),
                explanation = "The TLS certificate covers multiple names (${sans.take(5).joinToString(", ")}" +
                    "${if (sans.size > 5) "…" else ""}), revealing sibling hostnames that share it — useful for " +
                    "mapping the attack surface. This is disclosure inherent to public certificates, not a flaw per se.",
                remediation = "Where sibling hosts need not be publicly linked, issue separate certificates so one " +
                    "certificate does not enumerate the estate.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment",
            )
        }
        if (out.isEmpty()) notes += "No security-header or TLS issues flagged on the final response."
        return out
    }
}

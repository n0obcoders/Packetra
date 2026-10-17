package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Outcome
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification
import com.reconx.sentinel.core.network.HttpClients
import com.reconx.sentinel.core.security.ScopeValidator
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Deep, still-NON-DESTRUCTIVE web checks that complement [WebAssessor] (headers,
 * TLS) and [NiktoChecks] (paths): technology fingerprinting, detailed cookie
 * flags, CORS policy, API/doc discovery, outdated-component hints, and LIGHTWEIGHT
 * injection/XSS/open-redirect signals.
 *
 * Safety: every request is scope-validated, GET-only (plus one GraphQL POST of a
 * standard introspection query), response bodies are peeked and capped, and the
 * injection probes send a single inert token / lone quote / non-resolvable canary
 * host per parameter — enough to RAISE A SIGNAL to confirm manually, never to
 * exploit. Concurrency is bounded. This is a scanner, not an exploitation tool.
 */
class WebScanner(
    private val scope: ScopeValidator,
    private val dispatchers: DispatcherProvider,
    private val client: OkHttpClient = HttpClients.assessment(followRedirects = false),
) {
    data class Report(val techs: List<Fingerprinter.Tech>, val findings: List<Finding>, val notes: List<String>)

    private val sem = Semaphore(6)
    private val apiPaths = listOf(
        "swagger.json" to "Swagger/OpenAPI document",
        "openapi.json" to "OpenAPI document",
        "api-docs" to "API documentation",
        "v2/api-docs" to "Swagger v2 API docs",
        ".well-known/openapi.json" to "OpenAPI document",
    )
    private val canaryHost = "reconx-canary.invalid"

    suspend fun scan(url: String): Outcome<Report> {
        val base = url.trim()
        val decision = scope.validate(base)
        if (!decision.allowed) return Outcome.Err("refused: ${decision.reason}")
        return withContext(dispatchers.io) {
            try { Outcome.Ok(run(base)) }
            catch (t: Throwable) { Outcome.Err("deep scan of $base failed: ${t.message}", t) }
        }
    }

    private suspend fun run(url: String): Report = coroutineScope {
        val notes = mutableListOf<String>()
        val findings = mutableListOf<Finding>()
        var techs: List<Fingerprinter.Tech> = emptyList()

        // Base fetch: headers, body, raw Set-Cookie list.
        val baseResp = fetch(url)
        if (baseResp != null) {
            val https = url.startsWith("https://", true)
            techs = Fingerprinter.detect(baseResp.headers, baseResp.body, baseResp.setCookies)
            findings += CookieAnalyzer.analyze(url, https, baseResp.setCookies)
            techs.forEach { t ->
                VersionRules.outdated(t.name, t.version)?.let { why ->
                    findings += Finding(
                        id = "web-outdated-${(url + t.name + (t.version ?: "")).hashCode().toUInt().toString(16)}",
                        title = "Outdated component: ${t.name} ${t.version ?: ""}".trim(),
                        category = "vulnerable_component", severity = Severity.MEDIUM, confidence = Confidence.TENTATIVE,
                        target = url, evidence = mapOf("tech" to t.name, "version" to (t.version ?: ""), "from" to t.evidence),
                        explanation = why,
                        remediation = "Upgrade ${t.name} to a supported release and re-check against NVD.",
                        verification = Verification.UNVERIFIED, source = "web-assessment")
                }
            }
            // Cache-Control on a sensitive response.
            val host = url.toHttpUrlOrNull()?.host ?: ""
            val path = url.toHttpUrlOrNull()?.encodedPath ?: url
            val setsSession = baseResp.setCookies.any { c ->
                val n = c.substringBefore('=').trim()
                n.equals("sessionid", true) || n.equals("JSESSIONID", true) || n.equals("PHPSESSID", true) ||
                    n.equals("connect.sid", true) || n.startsWith("session", true) || n.endsWith("_session", true)
            }
            val sensitive = CacheControlAnalyzer.looksSensitive(path, setsSession, baseResp.body)
            CacheControlAnalyzer.analyze(url,
                baseResp.headers.entries.firstOrNull { it.key.equals("Cache-Control", true) }?.value,
                baseResp.headers.entries.firstOrNull { it.key.equals("Pragma", true) }?.value,
                sensitive)?.let { findings += it }

            // Client-side asset leakage + secret scanning: scan base body + a few linked same-origin scripts.
            val scriptUrls = AssetLeakAnalyzer.scriptUrls(url, baseResp.body)
            val jsText = scriptUrls.mapNotNull { s ->
                if (scope.validate(s).allowed) fetch(s)?.body else null
            }.joinToString("\n")
            val assetText = baseResp.body + "\n" + jsText
            findings += AssetLeakAnalyzer.analyze(url, host, assetText)
            findings += SecretScanner.scan(url, assetText)
            // Passive detection of meta-refresh / JavaScript redirects a plain GET-follower misses.
            findings += RedirectAnalyzer.analyze(url, host, baseResp.body)
        } else notes += "Base URL did not return a readable response for fingerprinting."

        // Multi-path sampling: a few key routes beyond root, so a path-specific gap
        // (a login page missing cache-control, an /api with a different header
        // posture) is not missed by only scanning "/". Scope-gated, GET-only; only
        // genuinely new issue types are kept so root-level gaps aren't repeated.
        val samplePaths = listOf("login", "api/", "admin", "dashboard", "checkout")
        val seenTitles = findings.map { it.title }.toMutableSet()
        val reached = mutableListOf<String>()
        for (p in samplePaths) {
            val target = url.trimEnd('/') + "/" + p
            if (!scope.validate(target).allowed) continue
            val r = fetch(target) ?: continue
            if (r.status !in 200..399) continue
            reached += p
            val https = target.startsWith("https://", true)
            (HeaderAnalyzer.analyze(target, https, r.headers) +
                CookieAnalyzer.analyze(target, https, r.setCookies)).forEach { f ->
                if (seenTitles.add(f.title)) findings += f
            }
        }
        notes += if (reached.isNotEmpty()) "Multi-path sampling reached: /${reached.joinToString(", /")}."
            else "Multi-path sampling: no extra key routes were reachable (only root sampled)."

        // Parallel: CORS, API discovery, injection signals.
        val jobs = buildList {
            add(async { corsCheck(url) })
            addAll(apiPaths.map { (p, label) -> async { apiCheck(url, p, label) } })
            add(async { graphqlCheck(url) })
            add(async { injectionSignals(url, notes) })
        }
        jobs.awaitAll().forEach { findings += it }

        Report(techs, findings.distinctBy { it.title + it.target }, notes)
    }

    // ---- individual checks ----

    private fun corsCheck(url: String): List<Finding> {
        val origin = "https://evil.example"
        val r = runCatching {
            client.newCall(req(url).header("Origin", origin).get().build()).execute().use {
                Triple(it.header("Access-Control-Allow-Origin"), it.header("Access-Control-Allow-Credentials"), it.code)
            }
        }.getOrNull() ?: return emptyList()
        return listOfNotNull(CorsAnalyzer.analyze(url, origin, r.first, r.second))
    }

    private fun apiCheck(base: String, path: String, label: String): List<Finding> {
        val target = base.trimEnd('/') + "/" + path
        if (!scope.validate(target).allowed) return emptyList()
        val r = fetch(target) ?: return emptyList()
        val looksJson = r.body.trimStart().startsWith("{") &&
            (r.body.contains("\"swagger\"") || r.body.contains("\"openapi\"") || r.body.contains("\"paths\""))
        if (r.status in 200..299 && looksJson)
            return listOf(Finding(
                id = "web-apidoc-${target.hashCode().toUInt().toString(16)}",
                title = "Exposed API specification ($label)", category = "exposure",
                severity = Severity.LOW, confidence = Confidence.FIRM, target = target,
                evidence = mapOf("path" to path, "status" to "${r.status}"),
                explanation = "An API specification is publicly readable, mapping every endpoint and parameter — " +
                    "useful to an attacker for targeting.",
                remediation = "Restrict API docs to authenticated internal users, or remove them from production.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment"))
        return emptyList()
    }

    private fun graphqlCheck(base: String): List<Finding> {
        val target = base.trimEnd('/') + "/graphql"
        if (!scope.validate(target).allowed) return emptyList()
        val body = "{\"query\":\"{__schema{queryType{name}}}\"}"
        val r = runCatching {
            val b = body.toRequestBody("application/json".toMediaType())
            client.newCall(req(target).post(b).build()).execute().use {
                it.code to (it.body?.source()?.peek()?.readByteString(8192L)?.utf8() ?: "")
            }
        }.getOrNull() ?: return emptyList()
        if (r.first in 200..299 && r.second.contains("__schema"))
            return listOf(Finding(
                id = "web-graphql-introspection-${target.hashCode().toUInt().toString(16)}",
                title = "GraphQL introspection enabled", category = "exposure",
                severity = Severity.LOW, confidence = Confidence.FIRM, target = target,
                evidence = mapOf("endpoint" to "/graphql"),
                explanation = "The GraphQL endpoint answers introspection queries, disclosing the full schema.",
                remediation = "Disable introspection in production or require authentication for it.",
                verification = Verification.VALIDATED_SAFELY, source = "web-assessment"))
        return emptyList()
    }

    /** One inert probe per query parameter: reflection (XSS hint), SQL-error, open redirect. */
    private suspend fun injectionSignals(url: String, notes: MutableList<String>): List<Finding> = coroutineScope {
        val httpUrl = url.toHttpUrlOrNull() ?: return@coroutineScope emptyList()
        val params = httpUrl.queryParameterNames.toList()
        if (params.isEmpty()) { notes += "No query parameters to test for injection signals."; return@coroutineScope emptyList() }
        val out = mutableListOf<Finding>()
        params.take(8).map { p ->
            async {
                val local = mutableListOf<Finding>()
                val marker = InjectionSignatures.marker((url + p).hashCode())
                // Reflected-input / XSS hint
                sem.withPermit { probeBody(setParam(httpUrl, p, marker)) }?.let { body ->
                    if (InjectionSignatures.reflectedUnencoded(body, marker)) {
                        val dangerous = InjectionSignatures.reflectedInDangerousContext(body, marker)
                        local += Finding(
                            id = "web-xss-${(url + p).hashCode().toUInt().toString(16)}",
                            title = "Reflected input in '$p'${if (dangerous) " (possible XSS)" else ""}",
                            category = "xss",
                            severity = if (dangerous) Severity.MEDIUM else Severity.LOW,
                            confidence = Confidence.TENTATIVE, target = url,
                            evidence = mapOf("parameter" to p, "context" to if (dangerous) "html/script" else "text"),
                            explanation = "The value of '$p' is reflected unencoded in the response" +
                                if (dangerous) ", inside an HTML/script context — a likely reflected-XSS point." else ".",
                            remediation = "Context-encode all reflected output and apply a Content-Security-Policy.",
                            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
                    }
                }
                // SQL-error hint (lone quote)
                sem.withPermit { probeBody(setParam(httpUrl, p, "'")) }?.let { body ->
                    InjectionSignatures.sqlError(body)?.let { sig ->
                        local += Finding(
                            id = "web-sqli-${(url + p).hashCode().toUInt().toString(16)}",
                            title = "Possible SQL injection in '$p'", category = "injection",
                            severity = Severity.HIGH, confidence = Confidence.TENTATIVE, target = url,
                            evidence = mapOf("parameter" to p, "signature" to sig),
                            explanation = "A single quote in '$p' triggered a database error ('$sig'), which suggests " +
                                "unsanitised input reaches a SQL query. Confirm manually before acting.",
                            remediation = "Use parameterised queries / prepared statements; never build SQL from input.",
                            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
                    }
                }
                // Open-redirect hint (canary host)
                sem.withPermit { probeLocation(setParam(httpUrl, p, "https://$canaryHost/")) }?.let { loc ->
                    if (InjectionSignatures.openRedirectTo(loc, canaryHost)) {
                        local += Finding(
                            id = "web-openredirect-${(url + p).hashCode().toUInt().toString(16)}",
                            title = "Open redirect via '$p'", category = "access_control",
                            severity = Severity.MEDIUM, confidence = Confidence.FIRM, target = url,
                            evidence = mapOf("parameter" to p, "location" to loc),
                            explanation = "Setting '$p' to an external URL made the server redirect to it, enabling " +
                                "phishing/redirect abuse.",
                            remediation = "Allow only relative or allow-listed redirect targets; reject absolute URLs.",
                            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
                    }
                }
                local
            }
        }.awaitAll().forEach { out += it }
        out
    }

    // ---- helpers ----

    private data class Resp(val status: Int, val headers: Map<String, String>, val body: String, val setCookies: List<String>)

    private fun req(url: String) = Request.Builder().url(url).header("User-Agent", HttpClients.USER_AGENT)

    private fun fetch(url: String): Resp? = runCatching {
        client.newCall(req(url).get().build()).execute().use { resp ->
            val headers = resp.headers.names().associateWith { resp.headers(it).joinToString("; ") }
            val body = resp.body?.source()?.peek()?.readByteString(65536L)?.utf8() ?: ""
            Resp(resp.code, headers, body, resp.headers("Set-Cookie"))
        }
    }.getOrNull()

    private fun probeBody(url: String): String? = runCatching {
        client.newCall(req(url).get().build()).execute().use {
            it.body?.source()?.peek()?.readByteString(65536L)?.utf8() ?: ""
        }
    }.getOrNull()

    private fun probeLocation(url: String): String? = runCatching {
        client.newCall(req(url).get().build()).execute().use { it.header("Location") }
    }.getOrNull()

    private fun setParam(httpUrl: okhttp3.HttpUrl, name: String, value: String): String =
        httpUrl.newBuilder().setQueryParameter(name, value).build().toString()
}

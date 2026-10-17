package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Outcome
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification
import com.reconx.sentinel.core.network.HttpClients
import com.reconx.sentinel.core.security.ScopeValidator
import okhttp3.OkHttpClient
import okhttp3.Request
import kotlinx.coroutines.withContext

/**
 * Nikto-style safe web checks: looks for commonly-exposed sensitive paths,
 * directory listing, risky HTTP methods and information disclosure. All checks
 * are bounded GET/OPTIONS requests against the authorized base URL — no fuzzing,
 * no state-changing methods, response sizes are capped. A present path or banner
 * is reported with evidence and confidence, never as a confirmed exploit.
 */
class NiktoChecks(
    private val scope: ScopeValidator,
    private val dispatchers: DispatcherProvider,
    private val client: OkHttpClient = HttpClients.assessment(followRedirects = false),
) {
    private data class PathCheck(val path: String, val title: String, val sev: Severity, val why: String)

    private val sensitivePaths = listOf(
        PathCheck(".git/HEAD", "Exposed .git repository", Severity.HIGH, "Source history may be downloadable."),
        PathCheck(".env", "Exposed .env file", Severity.HIGH, "Environment files often contain secrets."),
        PathCheck(".htaccess", "Readable .htaccess", Severity.MEDIUM, "Server config should not be world-readable."),
        PathCheck("web.config", "Exposed web.config", Severity.MEDIUM, "IIS config may disclose settings."),
        PathCheck("server-status", "Apache server-status exposed", Severity.MEDIUM, "Discloses live request data."),
        PathCheck("phpinfo.php", "phpinfo() exposed", Severity.MEDIUM, "Discloses full PHP configuration."),
        PathCheck("robots.txt", "robots.txt present", Severity.INFO, "May reveal hidden paths."),
        PathCheck(".well-known/security.txt", "security.txt present", Severity.INFO, "Security contact published."),
        PathCheck("backup.zip", "Backup archive exposed", Severity.HIGH, "Site backup may be downloadable."),
        PathCheck(".DS_Store", "Exposed .DS_Store", Severity.LOW, "May disclose directory structure."),
        PathCheck("sitemap.xml", "sitemap.xml present", Severity.INFO, "Enumerates site URLs for crawlers (and attackers)."),
    )

    suspend fun run(baseUrl: String): Outcome<List<Finding>> {
        val base = baseUrl.trim().trimEnd('/')
        val decision = scope.validate(base)
        if (!decision.allowed) return Outcome.Err("refused: ${decision.reason}")
        return withContext(dispatchers.io) {
            val out = mutableListOf<Finding>()
            // Sensitive paths
            for (c in sensitivePaths) {
                val r = head("$base/${c.path}") ?: continue
                if (r.first in 200..299) out += finding(base, c.title, "exposure", c.sev, c.why,
                    "Restrict or remove /${c.path} from the web root.", mapOf("path" to c.path, "status" to "${r.first}"))
            }
            // Directory listing + default page on root
            get(base)?.let { (status, body) ->
                if (body.contains("Index of /", true))
                    out += finding(base, "Directory listing enabled", "exposure", Severity.MEDIUM,
                        "The server returns an auto-generated directory index.",
                        "Disable automatic directory listing.", mapOf("status" to "$status"))
                if (body.contains("Welcome to nginx!", true) || body.contains("Apache2 Default Page", true))
                    out += finding(base, "Default web-server page", "information_disclosure", Severity.LOW,
                        "A default server page is served, suggesting an unconfigured host.",
                        "Replace the default page with the intended application.", mapOf("status" to "$status"))
            }
            // robots.txt: highlight Disallow entries that point at admin/internal routes.
            get("$base/robots.txt")?.let { (status, body) ->
                if (status in 200..299 && body.contains("Disallow", true)) {
                    val interesting = RobotsAnalyzer.interestingDisallows(body)
                    if (interesting.isNotEmpty())
                        out += finding(base, "robots.txt discloses sensitive paths", "information_disclosure",
                            Severity.LOW,
                            "robots.txt Disallow entries point at admin/internal routes: " +
                                "${interesting.take(8).joinToString(", ")}${if (interesting.size > 8) "…" else ""}.",
                            "Do not rely on robots.txt to hide sensitive paths; protect them with authentication " +
                                "and remove them from robots.txt.",
                            mapOf("paths" to interesting.joinToString(", ").take(400)))
                }
            }
            // HTTP methods via OPTIONS
            options(base)?.let { allow ->
                val risky = listOf("PUT", "DELETE", "TRACE", "CONNECT").filter { allow.contains(it, true) }
                if (risky.isNotEmpty())
                    out += finding(base, "Risky HTTP methods advertised", "misconfiguration", Severity.MEDIUM,
                        "OPTIONS advertised: ${risky.joinToString()}.",
                        "Disable unused HTTP methods (especially PUT/DELETE/TRACE).", mapOf("allow" to allow))
            }
            Outcome.Ok(out)
        }
    }

    private fun head(url: String): Pair<Int, Long>? = runCatching {
        client.newCall(Request.Builder().url(url).head()
            .header("User-Agent", HttpClients.USER_AGENT).build()).execute().use { it.code to (it.body?.contentLength() ?: 0) }
    }.getOrNull()

    private fun get(url: String): Pair<Int, String>? = runCatching {
        client.newCall(Request.Builder().url(url).get()
            .header("User-Agent", HttpClients.USER_AGENT).build()).execute().use {
            it.code to (it.body?.source()?.peek()?.readByteString(16384L)?.utf8() ?: "")
        }
    }.getOrNull()

    private fun options(url: String): String? = runCatching {
        client.newCall(Request.Builder().url(url).method("OPTIONS", null)
            .header("User-Agent", HttpClients.USER_AGENT).build()).execute().use { it.header("Allow") }
    }.getOrNull()

    private fun finding(url: String, title: String, cat: String, sev: Severity, why: String,
                        fix: String, ev: Map<String, String>) = Finding(
        id = "nikto-${(url + title).hashCode().toUInt().toString(16)}",
        title = title, category = cat, severity = sev, confidence = Confidence.FIRM,
        target = url, evidence = ev, explanation = why, remediation = fix,
        verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
}

package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Passive detection of non-HTTP redirects in already-fetched HTML: <meta
 * http-equiv="refresh"> and client-side JavaScript location changes. The HTTP
 * redirect chain is followed live by [WebAssessor]; this complements it by
 * REPORTING the meta/JS hops a plain GET-follower would miss (so an analyst can
 * see the full routing), and by flagging a redirect that leaves the target host
 * — a common open-redirect / phishing-pivot tell. It only reads markup; it does
 * not execute the script or follow the hop.
 */
object RedirectAnalyzer {
    data class Redirect(val kind: String, val target: String)

    private val META = Regex(
        """(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*?url\s*=\s*([^"';>\s]+)""")
    private val JS = listOf(
        Regex("""(?i)location\.href\s*=\s*["']([^"']+)["']"""),
        Regex("""(?i)location\.replace\s*\(\s*["']([^"']+)["']"""),
        Regex("""(?i)location\.assign\s*\(\s*["']([^"']+)["']"""),
        Regex("""(?i)window\.location\s*=\s*["']([^"']+)["']"""),
        Regex("""(?i)\bdocument\.location\s*=\s*["']([^"']+)["']"""),
    )

    /** Pure: find meta-refresh and JS redirect targets in a page body. */
    fun detect(body: String): List<Redirect> {
        val out = LinkedHashMap<String, Redirect>()
        META.findAll(body).forEach { m ->
            val t = m.groupValues[1].trim().trim('"', '\'')
            if (t.isNotEmpty()) out.putIfAbsent("meta|$t", Redirect("meta-refresh", t))
        }
        for (re in JS) re.findAll(body).forEach { m ->
            val t = m.groupValues[1].trim()
            if (t.isNotEmpty() && t != "#" && !t.startsWith("javascript:", true))
                out.putIfAbsent("js|$t", Redirect("javascript", t))
        }
        return out.values.take(20).toList()
    }

    /** Build findings; flags a redirect that points to a different host than [baseHost]. */
    fun analyze(url: String, baseHost: String, body: String): List<Finding> {
        val hops = detect(body)
        if (hops.isEmpty()) return emptyList()
        val offHost = hops.filter { r ->
            val h = hostOf(r.target)
            h != null && !h.equals(baseHost, true) && !h.endsWith(".$baseHost", true)
        }
        val out = mutableListOf<Finding>()
        out += Finding(
            id = "web-redirect-${url.hashCode().toUInt().toString(16)}",
            title = "Non-HTTP redirect(s) in page (${hops.map { it.kind }.distinct().joinToString(", ")})",
            category = "information_disclosure", severity = Severity.INFO, confidence = Confidence.FIRM,
            target = url,
            evidence = mapOf("hops" to hops.joinToString("; ") { "${it.kind}->${it.target}" }.take(400)),
            explanation = "The page redirects via ${hops.map { it.kind }.distinct().joinToString(" and ")} rather than an " +
                "HTTP status, which a plain crawler would miss. Listed so the full routing is visible.",
            remediation = "No action needed for legitimate routing; ensure the destination is intended.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
        if (offHost.isNotEmpty()) out += Finding(
            id = "web-redirect-offhost-${url.hashCode().toUInt().toString(16)}",
            title = "Client-side redirect leaves the site", category = "access_control",
            severity = Severity.LOW, confidence = Confidence.TENTATIVE, target = url,
            evidence = mapOf("targets" to offHost.joinToString(", ") { it.target }.take(400)),
            explanation = "A meta/JS redirect points off-site (${offHost.take(3).joinToString(", ") { it.target }}). If the " +
                "destination is derived from user input this is an open-redirect / phishing pivot; confirm it is static.",
            remediation = "Ensure redirect destinations are static or allow-listed, never built from request input.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
        return out
    }

    private fun hostOf(target: String): String? = runCatching {
        if (target.startsWith("//")) java.net.URI("https:$target").host
        else java.net.URI(target).host
    }.getOrNull()?.takeIf { it.isNotBlank() }
}

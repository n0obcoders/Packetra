package com.reconx.sentinel.feature.web

/**
 * Passive technology-stack fingerprinting from a single already-fetched response
 * (headers, body prefix and cookies). No extra requests, no active probing — it
 * only reads what the server already disclosed. Returns best-effort signals, not
 * certainties, so each carries the evidence it was derived from.
 */
object Fingerprinter {
    data class Tech(val name: String, val version: String? = null, val evidence: String = "")

    private val GENERATOR = Regex("(?is)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']")
    private val SERVER_VER = Regex("""([A-Za-z][A-Za-z0-9_+-]*)/(\d+[\d.]*)""")

    /** headers keys are matched case-insensitively. cookies = raw Set-Cookie values. */
    fun detect(headers: Map<String, String>, body: String, cookies: List<String>): List<Tech> {
        val h = headers.entries.associate { it.key.lowercase() to it.value }
        val out = LinkedHashMap<String, Tech>()
        fun add(t: Tech) { out.putIfAbsent(t.name + (t.version ?: ""), t) }

        h["server"]?.let { s ->
            SERVER_VER.findAll(s).forEach { m -> add(Tech(m.groupValues[1], m.groupValues[2], "Server: $s")) }
            if (!SERVER_VER.containsMatchIn(s)) add(Tech(s.trim(), null, "Server: $s"))
        }
        h["x-powered-by"]?.let { p ->
            SERVER_VER.findAll(p).forEach { m -> add(Tech(m.groupValues[1], m.groupValues[2], "X-Powered-By: $p")) }
            if (!SERVER_VER.containsMatchIn(p)) add(Tech(p.trim(), null, "X-Powered-By: $p"))
        }
        h["x-aspnet-version"]?.let { add(Tech("ASP.NET", it.trim(), "X-AspNet-Version: $it")) }
        h["x-aspnetmvc-version"]?.let { add(Tech("ASP.NET MVC", it.trim(), "X-AspNetMvc-Version: $it")) }
        h["x-generator"]?.let { add(Tech(it.trim(), null, "X-Generator: $it")) }
        if (h.containsKey("x-runtime") || h.containsKey("x-rack-cache")) add(Tech("Ruby on Rails", null, "Rack/Rails header"))
        h["x-drupal-cache"]?.let { add(Tech("Drupal", null, "X-Drupal-Cache header")) }

        // Cookie-based framework signals
        val cookieNames = cookies.mapNotNull { it.substringBefore('=').trim().takeIf { n -> n.isNotEmpty() } }
        cookieNames.forEach { cn ->
            when {
                cn.equals("PHPSESSID", true) -> add(Tech("PHP", null, "PHPSESSID cookie"))
                cn.equals("laravel_session", true) || cn.equals("XSRF-TOKEN", true) -> add(Tech("Laravel", null, "$cn cookie"))
                cn.equals("csrftoken", true) || cn.equals("sessionid", true) -> add(Tech("Django", null, "$cn cookie"))
                cn.startsWith("ASP.NET", true) || cn.equals("ASPSESSIONID", true) -> add(Tech("ASP.NET", null, "$cn cookie"))
                cn.equals("JSESSIONID", true) -> add(Tech("Java (Servlet)", null, "JSESSIONID cookie"))
                cn.startsWith("wordpress_", true) || cn.startsWith("wp-", true) -> add(Tech("WordPress", null, "$cn cookie"))
                cn.equals("connect.sid", true) -> add(Tech("Express (Node.js)", null, "connect.sid cookie"))
            }
        }

        // Body signals
        GENERATOR.find(body)?.groupValues?.get(1)?.let { g ->
            val parts = g.trim().split(' ', limit = 2)
            add(Tech(parts[0], parts.getOrNull(1)?.trim(), "meta generator: $g"))
        }
        if (body.contains("/wp-content/", true) || body.contains("/wp-includes/", true))
            add(Tech("WordPress", null, "wp-content/wp-includes paths"))
        if (body.contains("Drupal.settings", true) || body.contains("/sites/default/files", true))
            add(Tech("Drupal", null, "Drupal markers in body"))
        if (body.contains("csrfmiddlewaretoken", true)) add(Tech("Django", null, "csrfmiddlewaretoken in form"))
        if (body.contains("__NEXT_DATA__", true)) add(Tech("Next.js", null, "__NEXT_DATA__ in body"))
        if (body.contains("ng-version", true)) add(Tech("Angular", null, "ng-version attribute"))
        if (body.contains("data-reactroot", true) || body.contains("react", true) && body.contains("__REACT", true))
            add(Tech("React", null, "React markers in body"))

        // Client-side JS libraries (with versions) so VersionRules can flag outdated ones.
        detectClientLibs(body).forEach { add(it) }

        return out.values.toList()
    }

    // Match a library name + version embedded in a script URL, e.g.
    // jquery-3.4.1.min.js, jquery.min.js?ver=1.12.4, lodash.4.17.11.js,
    // bootstrap-4.3.1/, vue@2.6.10, react-16.8.0, angular.1.5.8.min.js.
    private data class LibPat(val name: String, val url: Regex, val inline: Regex? = null)

    private val CLIENT_LIBS = listOf(
        LibPat("jQuery",
            Regex("""(?i)jquery[-.]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)"""),
            Regex("""(?i)jquery[^\n]{0,40}?v?(\d+\.\d+\.\d+)""")),
        LibPat("jQuery UI", Regex("""(?i)jquery[-.]ui[-.]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)""")),
        LibPat("Lodash",
            Regex("""(?i)lodash[-.@]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)"""),
            Regex("""(?i)lodash[^\n]{0,30}?VERSION\s*[=:]\s*['"](\d+\.\d+\.\d+)['"]""")),
        LibPat("Underscore.js", Regex("""(?i)underscore[-.@]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)""")),
        LibPat("Bootstrap", Regex("""(?i)bootstrap[-.@]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)""")),
        LibPat("AngularJS", Regex("""(?i)angular[-.@]?(?:min[-.]?)?v?(1\.\d+(?:\.\d+)?)""")),
        LibPat("Vue.js", Regex("""(?i)vue[-.@]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)""")),
        LibPat("Moment.js", Regex("""(?i)moment[-.@]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)""")),
        LibPat("Handlebars", Regex("""(?i)handlebars[-.@]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)""")),
        LibPat("DOMPurify", Regex("""(?i)(?:purify|dompurify)[-.@]?(?:min[-.]?)?v?(\d+\.\d+(?:\.\d+)?)""")),
    )

    /** Pure: detect common client-side libraries and their versions from HTML/JS text. */
    fun detectClientLibs(text: String): List<Tech> {
        val out = LinkedHashMap<String, Tech>()
        // Prefer <script src> matches (most reliable), then inline banner/version markers.
        val srcs = Regex("""(?i)<script[^>]+src\s*=\s*["']([^"']+)["']""")
            .findAll(text).map { it.groupValues[1] }.toList()
        for (lib in CLIENT_LIBS) {
            var version: String? = null
            var evidence = ""
            for (s in srcs) {
                val m = lib.url.find(s)
                if (m != null) { version = m.groupValues[1]; evidence = "script src: ${s.take(120)}"; break }
            }
            if (version == null && lib.inline != null) {
                lib.inline!!.find(text)?.let { version = it.groupValues[1]; evidence = "inline version marker" }
            }
            version?.let { out.putIfAbsent(lib.name, Tech(lib.name, it, evidence)) }
        }
        return out.values.toList()
    }
}

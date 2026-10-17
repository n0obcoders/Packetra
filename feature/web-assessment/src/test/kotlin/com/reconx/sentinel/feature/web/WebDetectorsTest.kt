package com.reconx.sentinel.feature.web

import com.google.common.truth.Truth.assertThat
import com.reconx.sentinel.core.common.Severity
import org.junit.Test

class WebDetectorsTest {

    @Test fun `fingerprinter reads server, powered-by, cookies and body`() {
        val techs = Fingerprinter.detect(
            headers = mapOf("Server" to "nginx/1.18.0", "X-Powered-By" to "PHP/7.2.1"),
            body = "<html><meta name=\"generator\" content=\"WordPress 6.2\"><a href=\"/wp-content/x\">",
            cookies = listOf("PHPSESSID=abc; path=/", "laravel_session=zzz"),
        )
        val names = techs.map { it.name.lowercase() }
        assertThat(names).containsAtLeast("nginx", "php", "wordpress", "laravel")
        assertThat(techs.first { it.name.equals("nginx", true) }.version).isEqualTo("1.18.0")
    }

    @Test fun `cookie analyzer flags missing flags`() {
        val f = CookieAnalyzer.analyze("https://t.example", https = true,
            setCookies = listOf("sid=abc; Path=/"))
        assertThat(f).hasSize(1)
        assertThat(f[0].evidence["missing"]).contains("Secure")
        assertThat(f[0].evidence["missing"]).contains("HttpOnly")
        assertThat(f[0].evidence["missing"]).contains("SameSite")
    }

    @Test fun `cookie analyzer passes a well-set cookie`() {
        val f = CookieAnalyzer.analyze("https://t.example", https = true,
            setCookies = listOf("sid=abc; Secure; HttpOnly; SameSite=Lax"))
        assertThat(f).isEmpty()
    }

    @Test fun `cors reflects arbitrary origin with credentials is HIGH`() {
        val f = CorsAnalyzer.analyze("https://t.example", "https://evil.example",
            acao = "https://evil.example", acac = "true")
        assertThat(f).isNotNull()
        assertThat(f!!.severity).isEqualTo(Severity.HIGH)
    }

    @Test fun `cors same-origin policy is not flagged`() {
        val f = CorsAnalyzer.analyze("https://t.example", "https://evil.example",
            acao = "https://t.example", acac = "true")
        assertThat(f).isNull()
    }

    @Test fun `injection signatures detect reflection, sql error and open redirect`() {
        val m = InjectionSignatures.marker(42)
        assertThat(InjectionSignatures.reflectedUnencoded("hello $m world", m)).isTrue()
        assertThat(InjectionSignatures.reflectedInDangerousContext("<div>$m</div>", m)).isTrue()
        assertThat(InjectionSignatures.sqlError("Warning: mysql_fetch_array() expects"))
            .isNotNull()
        assertThat(InjectionSignatures.sqlError("all good")).isNull()
        assertThat(InjectionSignatures.openRedirectTo("https://reconx-canary.invalid/x", "reconx-canary.invalid")).isTrue()
        assertThat(InjectionSignatures.openRedirectTo("/local/path", "reconx-canary.invalid")).isFalse()
    }

    @Test fun `version rules flag an outdated nginx but not a current one`() {
        assertThat(VersionRules.outdated("nginx", "1.18.0")).isNotNull()
        assertThat(VersionRules.outdated("nginx", "1.25.0")).isNull()
        assertThat(VersionRules.outdated("php", "7.2")).isNotNull()
        assertThat(VersionRules.outdated("UnknownThing", "1.0")).isNull()
    }

    @Test fun `cache-control flags a sensitive route without no-store`() {
        val sensitive = CacheControlAnalyzer.looksSensitive("/account/profile", false, "")
        assertThat(sensitive).isTrue()
        val f = CacheControlAnalyzer.analyze("https://t.example/account", "private, max-age=600", null, sensitive)
        assertThat(f).isNotNull()
        assertThat(f!!.category).isEqualTo("information_disclosure")
    }

    @Test fun `cache-control passes when no-store present or route not sensitive`() {
        assertThat(CacheControlAnalyzer.analyze("https://t.example/account", "no-store", null, true)).isNull()
        assertThat(CacheControlAnalyzer.analyze("https://t.example/public", null, null, false)).isNull()
    }

    @Test fun `cache-control treats a session cookie as sensitive`() {
        assertThat(CacheControlAnalyzer.looksSensitive("/", true, "")).isTrue()
    }

    @Test fun `asset leak finds sourcemaps, internal hosts and private IPs`() {
        val text = """
            <script src="/static/app.min.js"></script>
            //# sourceMappingURL=app.min.js.map
            var api = "https://api-staging.example.com/v1";
            var dev = "http://127.0.0.1:8080/debug";
        """.trimIndent()
        val f = AssetLeakAnalyzer.analyze("https://shop.example.com/", "shop.example.com", text)
        val titles = f.map { it.title }
        assertThat(titles).contains("Source maps exposed")
        assertThat(titles).contains("Internal/staging host references in client assets")
        assertThat(titles).contains("Hardcoded localhost/private IP in client assets")
    }

    @Test fun `asset leak does not flag the base host itself`() {
        val text = """<a href="https://shop.example.com/about">home</a>"""
        val f = AssetLeakAnalyzer.analyze("https://shop.example.com/", "shop.example.com", text)
        assertThat(f).isEmpty()
    }

    @Test fun `script urls extracts same-origin js only`() {
        val body = """
            <script src="/js/app.js"></script>
            <script src="https://cdn.other.com/jquery.js"></script>
            <script src="https://shop.example.com/vendor.js"></script>
        """.trimIndent()
        val urls = AssetLeakAnalyzer.scriptUrls("https://shop.example.com/", body)
        assertThat(urls).contains("https://shop.example.com/js/app.js")
        assertThat(urls).contains("https://shop.example.com/vendor.js")
        assertThat(urls.none { it.contains("cdn.other.com") }).isTrue()
    }

    @Test fun `robots analyzer highlights admin disallows only`() {
        val robots = """
            User-agent: *
            Disallow: /
            Disallow: /admin/
            Disallow: /wp-admin/
            Disallow: /images/
            Disallow: /backup.zip
        """.trimIndent()
        val interesting = RobotsAnalyzer.interestingDisallows(robots)
        assertThat(interesting).containsAtLeast("/admin/", "/wp-admin/", "/backup.zip")
        assertThat(interesting).doesNotContain("/images/")
        assertThat(interesting).doesNotContain("/")
    }

    @Test fun `fingerprinter detects client-side library versions`() {
        val libs = Fingerprinter.detectClientLibs(
            "<script src=\"/assets/jquery-1.12.4.min.js\"></script>" +
                "<script src=\"https://cdn/lodash.4.17.11.js\"></script>" +
                "<script src=\"/bootstrap-3.3.7.min.js\"></script>")
        val byName = libs.associate { it.name to it.version }
        assertThat(byName["jQuery"]).isEqualTo("1.12.4")
        assertThat(byName["Lodash"]).isEqualTo("4.17.11")
        assertThat(byName["Bootstrap"]).isEqualTo("3.3.7")
    }

    @Test fun `version rules flag vulnerable client libraries`() {
        assertThat(VersionRules.outdated("jQuery", "1.12.4")).isNotNull()
        assertThat(VersionRules.outdated("jQuery", "3.7.1")).isNull()
        assertThat(VersionRules.outdated("Lodash", "4.17.11")).isNotNull()
        assertThat(VersionRules.outdated("Lodash", "4.17.21")).isNull()
        // "jQuery UI" must not be matched by the "jquery" rule.
        assertThat(VersionRules.outdated("jQuery UI", "1.13.2")).isNull()
    }

    @Test fun `fix snippets exist for common findings and cover four platforms`() {
        val hsts = com.reconx.sentinel.core.common.Finding(
            id = "x", title = "HSTS not set", category = "transport_security",
            severity = Severity.MEDIUM,
            confidence = com.reconx.sentinel.core.common.Confidence.FIRM, target = "u")
        val s = FixSnippets.forFinding(hsts)
        assertThat(s).isNotNull()
        assertThat(s!!.keys).containsAtLeast("Nginx", "Apache", "Caddy", "Cloudflare")
        assertThat(s["Nginx"]).contains("Strict-Transport-Security")
    }

    @Test fun `secret scanner finds real keys and redacts them`() {
        val text = """
            const AWS = "AKIAIOSFODNN7EXAMPLE";
            var g = "AIza01234567890123456789012345678901234";
            token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        """.trimIndent()
        val hits = SecretScanner.findSecrets(text)
        val names = hits.map { it.rule }
        assertThat(names).containsAtLeast("AWS access key ID", "Google API key", "GitHub token")
        // Redacted — the full secret is not echoed back.
        assertThat(hits.none { it.redacted.contains("AKIAIOSFODNN7EXAMPLE") }).isTrue()
    }

    @Test fun `secret scanner ignores obvious placeholders`() {
        val hits = SecretScanner.findSecrets("""apiKey = "your_api_key_here"; password = "xxxxxxxxxxxx";""")
        assertThat(hits).isEmpty()
    }

    @Test fun `secret scanner flags a generic high-entropy assignment`() {
        val hits = SecretScanner.findSecrets("""client_secret = "aB3dE7gH9kL2mN5pQ8rS1tU4";""")
        assertThat(hits.map { it.rule }).contains("Generic hardcoded secret")
    }

    @Test fun `csp analyzer flags wildcard subdomain trust and unsafe-inline`() {
        val csp = "default-src 'self'; script-src 'self' 'unsafe-inline' *.example.com https://cdn.example.net"
        val bases = CspAnalyzer.wildcardSubdomainBases(csp)
        assertThat(bases).contains("example.com")
        val f = CspAnalyzer.analyze("https://example.com", csp)
        val titles = f.map { it.title }
        assertThat(titles.any { it.contains("trusts all subdomains") }).isTrue()
        assertThat(titles.any { it.contains("unsafe-inline") }).isTrue()
    }

    @Test fun `csp analyzer is quiet on a tight policy`() {
        val csp = "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'"
        val f = CspAnalyzer.analyze("https://example.com", csp)
        assertThat(f.none { it.title.contains("unsafe") || it.title.contains("subdomains") || it.title.contains("broad") }).isTrue()
    }

    @Test fun `redirect analyzer detects meta-refresh and js redirects`() {
        val body = """
            <meta http-equiv="refresh" content="0; url=/dashboard">
            <script>location.href = "https://evil.example/landing";</script>
        """.trimIndent()
        val hops = RedirectAnalyzer.detect(body)
        assertThat(hops.map { it.kind }).containsAtLeast("meta-refresh", "javascript")
        val f = RedirectAnalyzer.analyze("https://shop.example.com/", "shop.example.com", body)
        assertThat(f.any { it.title.contains("leaves the site") }).isTrue()
    }

    @Test fun `redirect analyzer is quiet on a plain page`() {
        assertThat(RedirectAnalyzer.detect("<html><body>hello</body></html>")).isEmpty()
    }

    @Test fun `risk prioritizer ranks confirmed high above tentative and groups duplicates`() {
        val confirmedHigh = com.reconx.sentinel.core.common.Finding(
            id = "a", title = "SQL error leak", category = "injection", severity = Severity.HIGH,
            confidence = com.reconx.sentinel.core.common.Confidence.CONFIRMED, target = "u1",
            verification = com.reconx.sentinel.core.common.Verification.CONFIRMED)
        val tentativeHigh = com.reconx.sentinel.core.common.Finding(
            id = "b", title = "Possible injection", category = "injection", severity = Severity.HIGH,
            confidence = com.reconx.sentinel.core.common.Confidence.TENTATIVE, target = "u2",
            verification = com.reconx.sentinel.core.common.Verification.UNVERIFIED)
        assertThat(RiskPrioritizer.score(confirmedHigh)).isGreaterThan(RiskPrioritizer.score(tentativeHigh))

        val dupA = tentativeHigh.copy(id = "c", target = "u3")
        val groups = RiskPrioritizer.prioritize(listOf(confirmedHigh, tentativeHigh, dupA))
        // tentativeHigh + dupA share a normalized key and collapse into one group.
        assertThat(groups.size).isEqualTo(2)
        assertThat(groups.first().representative.id).isEqualTo("a")  // highest priority first
    }

    @Test fun `permissions-policy missing is flagged and a restrictive one passes`() {
        val missing = HeaderAnalyzer.analyze("https://x", true, mapOf("Content-Type" to "text/html"))
        assertThat(missing.any { it.title == "Permissions-Policy not set" }).isTrue()
        val wideOpen = HeaderAnalyzer.analyze("https://x", true,
            mapOf("Permissions-Policy" to "geolocation=*"))
        assertThat(wideOpen.any { it.title.contains("Permissions-Policy") && it.title.contains("weak") }).isTrue()
        val good = HeaderAnalyzer.analyze("https://x", true,
            mapOf("Permissions-Policy" to "geolocation=(), camera=(), microphone=(), payment=()"))
        assertThat(good.none { it.title.contains("Permissions-Policy") }).isTrue()
    }

    @Test fun `weak tls cipher detection`() {
        assertThat(TlsCipherRules.weakness("TLS_RSA_WITH_RC4_128_SHA")).isNotNull()
        assertThat(TlsCipherRules.weakness("TLS_RSA_WITH_3DES_EDE_CBC_SHA")).isNotNull()
        assertThat(TlsCipherRules.weakness("SSL_RSA_WITH_NULL_MD5")).isNotNull()
        assertThat(TlsCipherRules.weakness("TLS_AES_128_GCM_SHA256")).isNull()
        assertThat(TlsCipherRules.weakness("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")).isNull()
    }

    @Test fun `redirect chain validator flags no-upgrade and accepts upgrade`() {
        val noUpgrade = RedirectChainValidator.analyze("http://x", listOf("http://x", "http://x/home"), false)
        assertThat(noUpgrade).hasSize(1)
        assertThat(noUpgrade.first().severity).isEqualTo(Severity.HIGH)
        val upgraded = RedirectChainValidator.analyze("https://x", listOf("http://x", "https://x"), true)
        assertThat(upgraded).isEmpty()
        assertThat(RedirectChainValidator.upgradedCleanly(listOf("http://x", "https://x"), true)).isTrue()
        assertThat(RedirectChainValidator.analyze("https://x", listOf("https://x"), true)).isEmpty()
    }

    @Test fun `passed checks summary reports well-configured controls`() {
        val headers = mapOf(
            "Strict-Transport-Security" to "max-age=63072000",
            "X-Content-Type-Options" to "nosniff",
            "Content-Security-Policy" to "default-src 'self'",
            "Set-Cookie" to "sid=abc; Secure; HttpOnly; SameSite=Lax",
        )
        val tls = TlsInfo(version = "TLSv1.3", cipher = "TLS_AES_128_GCM_SHA256",
            subject = null, issuer = null, notAfter = null, daysToExpiry = 200)
        val passed = PassedChecksAnalyzer.analyze(true, headers, tls, listOf("http://x", "https://x"))
        val names = passed.map { it.name }
        assertThat(names).contains("HTTPS in use")
        assertThat(names).contains("Strict-Transport-Security present")
        assertThat(names).contains("Cookie Secure flag")
        assertThat(names).contains("Strong cipher suite")
        assertThat(names).contains("HTTP upgraded to HTTPS")
    }

    @Test fun `cvss maps injection to critical-ish and info to zero`() {
        val inj = Cvss.forFinding(com.reconx.sentinel.core.common.Finding(
            id = "x", title = "t", category = "injection", severity = Severity.HIGH,
            confidence = com.reconx.sentinel.core.common.Confidence.TENTATIVE, target = "u"))
        assertThat(inj.base).isAtLeast(9.0)
        val info = Cvss.forFinding(com.reconx.sentinel.core.common.Finding(
            id = "x", title = "t", category = "information_disclosure", severity = Severity.INFO,
            confidence = com.reconx.sentinel.core.common.Confidence.CONFIRMED, target = "u"))
        assertThat(info.base).isAtMost(3.5)
    }
}

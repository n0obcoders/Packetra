package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Finding

/**
 * Concrete, copy-pasteable remediation config for the common web findings, per
 * platform (Nginx, Apache, Caddy, Cloudflare). These are starting-point snippets
 * an engineer adapts to their stack — they are deliberately conservative and
 * standards-aligned. Pure/offline: it maps a finding to known-good config, it
 * does not generate exploits.
 */
object FixSnippets {
    /** platform display name -> config block */
    fun forFinding(f: Finding): Map<String, String>? {
        val t = f.title.lowercase()
        return when {
            t.contains("hsts") || t.contains("strict-transport") ->
                header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            t.contains("content-security-policy") || t.contains("csp") ->
                header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'")
            t.contains("x-content-type-options") ->
                header("X-Content-Type-Options", "nosniff")
            t.contains("clickjacking") || t.contains("x-frame-options") || t.contains("frame-ancestors") ->
                header("X-Frame-Options", "SAMEORIGIN")
            t.contains("referrer-policy") ->
                header("Referrer-Policy", "strict-origin-when-cross-origin")
            f.category == "information_disclosure" && t.contains("cache") ->
                header("Cache-Control", "no-store, no-cache, must-revalidate")
            t.contains("cookie") -> cookieSnippet()
            t.contains("cors") || f.category == "cors" -> corsSnippet()
            t.contains("tls 1.0") || t.contains("tls 1.1") || t.contains("legacy") && t.contains("tls") -> tlsSnippet()
            t.contains("directory listing") -> dirListingSnippet()
            t.contains(".git") || t.contains(".env") || t.contains("exposed") && f.category == "exposure" -> denyPathSnippet()
            else -> null
        }
    }

    private fun header(name: String, value: String): Map<String, String> = mapOf(
        "Nginx" to "add_header $name \"$value\" always;",
        "Apache" to "Header always set $name \"$value\"",
        "Caddy" to "header $name \"$value\"",
        "Cloudflare" to "# Transform Rules → Modify Response Header → Set static\n# Header name: $name\n# Value: $value",
    )

    private fun cookieSnippet(): Map<String, String> = mapOf(
        "Nginx" to "# When the app sets the cookie, add flags; for proxy_pass you can rewrite:\nproxy_cookie_flags ~ secure httponly samesite=lax;",
        "Apache" to "Header always edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
        "Caddy" to "# Best set by the application; or via header manipulation:\nheader +Set-Cookie \"; Secure; HttpOnly; SameSite=Lax\"",
        "Cloudflare" to "# Set the flags in the origin application. Cloudflare can enforce Secure via\n# \"Always Use HTTPS\" but cannot reliably append HttpOnly to app cookies.",
    )

    private fun corsSnippet(): Map<String, String> = mapOf(
        "Nginx" to "# Reflect ONLY an allow-listed origin; never echo arbitrary Origin with credentials.\nset \$cors \"\";\nif (\$http_origin = \"https://app.example.com\") { set \$cors \$http_origin; }\nadd_header Access-Control-Allow-Origin \$cors always;\nadd_header Access-Control-Allow-Credentials true always;",
        "Apache" to "SetEnvIf Origin \"^https://app\\.example\\.com$\" CORS_ORIGIN=$0\nHeader always set Access-Control-Allow-Origin %{CORS_ORIGIN}e env=CORS_ORIGIN\nHeader always set Access-Control-Allow-Credentials true env=CORS_ORIGIN",
        "Caddy" to "@cors header Origin https://app.example.com\nheader @cors Access-Control-Allow-Origin \"https://app.example.com\"\nheader @cors Access-Control-Allow-Credentials true",
        "Cloudflare" to "// Workers: allow-list, never reflect + credentials for '*'\nconst allowed = ['https://app.example.com'];\nconst o = request.headers.get('Origin');\nif (allowed.includes(o)) { res.headers.set('Access-Control-Allow-Origin', o); res.headers.set('Access-Control-Allow-Credentials','true'); }",
    )

    private fun tlsSnippet(): Map<String, String> = mapOf(
        "Nginx" to "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;",
        "Apache" to "SSLProtocol -all +TLSv1.2 +TLSv1.3",
        "Caddy" to "tls {\n    protocols tls1.2 tls1.3\n}",
        "Cloudflare" to "# SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2",
    )

    private fun dirListingSnippet(): Map<String, String> = mapOf(
        "Nginx" to "autoindex off;",
        "Apache" to "Options -Indexes",
        "Caddy" to "# Caddy does not list directories unless 'file_server browse' is set — remove 'browse'.",
        "Cloudflare" to "# Directory listing is an origin setting; disable it on the origin web server.",
    )

    private fun denyPathSnippet(): Map<String, String> = mapOf(
        "Nginx" to "location ~ /\\.(git|env|htaccess|DS_Store) { deny all; return 404; }",
        "Apache" to "<FilesMatch \"^\\.(git|env|htaccess|DS_Store)\">\n    Require all denied\n</FilesMatch>",
        "Caddy" to "@hidden path /.git* /.env /.htaccess /.DS_Store\nrespond @hidden 404",
        "Cloudflare" to "# WAF custom rule: (http.request.uri.path contains \"/.git\" or http.request.uri.path contains \"/.env\") → Block",
    )
}

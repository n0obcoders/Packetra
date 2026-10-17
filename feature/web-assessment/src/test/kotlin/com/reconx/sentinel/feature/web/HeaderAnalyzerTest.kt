package com.reconx.sentinel.feature.web

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class HeaderAnalyzerTest {
    @Test fun `missing hsts flagged on https`() {
        val f = HeaderAnalyzer.analyze("https://app.example.com", true, emptyMap())
        assertThat(f.map { it.title }).contains("HSTS not set")
    }
    @Test fun `good headers produce no header findings`() {
        val headers = mapOf(
            "Strict-Transport-Security" to "max-age=63072000; includeSubDomains",
            "Content-Security-Policy" to "default-src 'self'",
            "X-Content-Type-Options" to "nosniff",
            "X-Frame-Options" to "DENY",
            "Referrer-Policy" to "strict-origin-when-cross-origin",
            "Permissions-Policy" to "geolocation=(), camera=(), microphone=(), payment=()")
        val f = HeaderAnalyzer.analyze("https://app.example.com", true, headers)
        assertThat(f.none { it.category == "security_header" }).isTrue()
    }
    @Test fun `server header is information disclosure`() {
        val f = HeaderAnalyzer.analyze("https://app.example.com", true,
            mapOf("Server" to "nginx/1.18.0"))
        assertThat(f.any { it.category == "information_disclosure" }).isTrue()
    }
    @Test fun `plaintext http flagged`() {
        val f = HeaderAnalyzer.analyze("http://app.example.com", false, emptyMap())
        assertThat(f.any { it.category == "transport_security" }).isTrue()
    }
    @Test fun `insecure cookie flagged and value redacted`() {
        val f = HeaderAnalyzer.analyze("https://app.example.com", true,
            mapOf("Set-Cookie" to "sid=abc123; Path=/"))
        val cookie = f.first { it.category == "cookie_security" }
        assertThat(cookie.evidence.values.none { it.contains("abc123") }).isTrue()
    }
}

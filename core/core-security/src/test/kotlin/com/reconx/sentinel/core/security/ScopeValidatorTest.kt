package com.reconx.sentinel.core.security

import com.google.common.truth.Truth.assertThat
import java.net.InetAddress
import org.junit.Test

class ScopeValidatorTest {

    private fun resolver(map: Map<String, String>): (String) -> List<InetAddress> =
        { host -> map[host]?.let { listOf(InetAddress.getByName(it)) } ?: emptyList() }

    @Test fun `domain suffix in scope is allowed`() {
        val v = ScopeValidator(ScopePolicy(1, domains = setOf("example.com")),
            resolver(mapOf("app.example.com" to "203.0.113.10")))
        assertThat(v.validate("app.example.com").allowed).isTrue()
        assertThat(v.validate("example.com").allowed).isTrue()
    }

    @Test fun `unrelated domain is denied by default`() {
        val v = ScopeValidator(ScopePolicy(1, domains = setOf("example.com")),
            resolver(mapOf("evil.test" to "203.0.113.99")))
        assertThat(v.validate("evil.test").allowed).isFalse()
    }

    @Test fun `lookalike suffix is not matched`() {
        val v = ScopeValidator(ScopePolicy(1, domains = setOf("example.com")),
            resolver(mapOf("notexample.com" to "203.0.113.5")))
        assertThat(v.validate("notexample.com").allowed).isFalse()
    }

    @Test fun `cidr literal in scope is allowed`() {
        val v = ScopeValidator(ScopePolicy(1, cidrs = listOf("203.0.113.0/24")))
        assertThat(v.validate("203.0.113.42").allowed).isTrue()
        assertThat(v.validate("203.0.114.1").allowed).isFalse()
    }

    @Test fun `private address blocked unless lab opt-in`() {
        val p = ScopePolicy(1, cidrs = listOf("192.168.0.0/16"))
        assertThat(ScopeValidator(p).validate("192.168.1.10").allowed).isFalse()
        val lab = p.copy(allowPrivateForLab = true)
        assertThat(ScopeValidator(lab).validate("192.168.1.10").allowed).isTrue()
    }

    @Test fun `metadata endpoint always denied even inside an allowed cidr`() {
        val v = ScopeValidator(ScopePolicy(1, cidrs = listOf("169.254.0.0/16"),
            allowPrivateForLab = true))
        assertThat(v.validate("169.254.169.254").allowed).isFalse()
    }

    @Test fun `exclusion overrides include`() {
        val v = ScopeValidator(ScopePolicy(1, domains = setOf("example.com"),
            exclusions = setOf("secret.example.com")),
            resolver(mapOf("secret.example.com" to "203.0.113.7",
                "ok.example.com" to "203.0.113.8")))
        assertThat(v.validate("secret.example.com").allowed).isFalse()
        assertThat(v.validate("ok.example.com").allowed).isTrue()
    }

    @Test fun `url and port are stripped before matching`() {
        val v = ScopeValidator(ScopePolicy(1, domains = setOf("example.com")),
            resolver(mapOf("app.example.com" to "203.0.113.10")))
        assertThat(v.validate("https://app.example.com:8443/login").allowed).isTrue()
    }

    @Test fun `empty scope denies by default`() {
        val v = ScopeValidator(ScopePolicy(1), resolver(mapOf("scanme.nmap.org" to "45.33.32.156")))
        assertThat(v.validate("scanme.nmap.org").allowed).isFalse()
    }
}

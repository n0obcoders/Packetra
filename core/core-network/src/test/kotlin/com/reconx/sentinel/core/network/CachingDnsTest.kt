package com.reconx.sentinel.core.network

import com.google.common.truth.Truth.assertThat
import java.net.InetAddress
import okhttp3.Dns
import org.junit.Test

class CachingDnsTest {
    private class CountingDns(private val addr: String) : Dns {
        var calls = 0; private set
        override fun lookup(hostname: String): List<InetAddress> {
            calls++
            return listOf(InetAddress.getByName(addr))
        }
    }

    @Test fun `resolves once within ttl then again after expiry`() {
        val delegate = CountingDns("203.0.113.5")
        var now = 1_000L
        val dns = CachingDns(ttlMillis = 100, delegate = delegate, clock = { now })

        dns.lookup("example.com")
        dns.lookup("example.com")
        assertThat(delegate.calls).isEqualTo(1)   // second served from cache

        now += 101                                 // past TTL
        dns.lookup("example.com")
        assertThat(delegate.calls).isEqualTo(2)   // re-resolved after expiry
    }

    @Test fun `distinct hosts are cached independently`() {
        val delegate = CountingDns("203.0.113.6")
        val dns = CachingDns(ttlMillis = 10_000, delegate = delegate, clock = { 0L })
        dns.lookup("a.test")
        dns.lookup("b.test")
        assertThat(delegate.calls).isEqualTo(2)
        assertThat(dns.size()).isEqualTo(2)
    }
}

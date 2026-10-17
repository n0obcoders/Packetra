package com.reconx.sentinel.core.security

import com.google.common.truth.Truth.assertThat
import java.net.InetAddress
import org.junit.Test

class CidrTest {
    @Test fun `ipv4 containment`() {
        val c = Cidr.parseOrNull("10.0.0.0/8")!!
        assertThat(c.contains(InetAddress.getByName("10.255.1.1"))).isTrue()
        assertThat(c.contains(InetAddress.getByName("11.0.0.1"))).isFalse()
    }
    @Test fun `host route slash 32`() {
        val c = Cidr.parseOrNull("203.0.113.5/32")!!
        assertThat(c.contains(InetAddress.getByName("203.0.113.5"))).isTrue()
        assertThat(c.contains(InetAddress.getByName("203.0.113.6"))).isFalse()
    }
    @Test fun `ipv6 containment`() {
        val c = Cidr.parseOrNull("2001:db8::/32")!!
        assertThat(c.contains(InetAddress.getByName("2001:db8:1::1"))).isTrue()
        assertThat(c.contains(InetAddress.getByName("2001:db9::1"))).isFalse()
    }
    @Test fun `malformed returns null`() {
        assertThat(Cidr.parseOrNull("not-a-cidr")).isNull()
        assertThat(Cidr.parseOrNull("10.0.0.0/40")).isNull()
    }
    @Test fun `v4 rule does not match v6 address`() {
        val c = Cidr.parseOrNull("0.0.0.0/0")!!
        assertThat(c.contains(InetAddress.getByName("2001:db8::1"))).isFalse()
    }
}

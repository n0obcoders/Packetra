package com.reconx.sentinel.feature.capture

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class PacketParserTest {
    @Test fun `parses ipv4 tcp 5-tuple`() {
        val p = ByteArray(40)
        p[0] = 0x45                  // v4, ihl=5
        p[9] = 6                     // TCP
        p[16] = 203.toByte(); p[17]=0; p[18]=113.toByte(); p[19]=7  // dst 203.0.113.7
        p[20] = 0x1F; p[21] = 0x90.toByte()   // sport 8080
        p[22] = 0x01; p[23] = 0xBB.toByte()   // dport 443
        val parsed = PacketParser.parseOutbound(p, 40)!!
        assertThat(parsed.protocol).isEqualTo("TCP")
        assertThat(parsed.destIp).isEqualTo("203.0.113.7")
        assertThat(parsed.destPort).isEqualTo(443)
    }
    @Test fun `short packet returns null`() {
        assertThat(PacketParser.parseOutbound(ByteArray(8), 8)).isNull()
    }
    @Test fun `tracker aggregates bytes per flow`() {
        val t = ConnectionTracker()
        val k = ConnKey("TCP", "10.0.0.1", 5000, "203.0.113.7", 443)
        t.record(k, 100, outbound = true, host = null)
        t.record(k, 250, outbound = false, host = "example.com")
        val f = t.snapshot().first()
        assertThat(f.host).isEqualTo("example.com")
        assertThat(f.bytesOut).isEqualTo(100)
        assertThat(f.bytesIn).isEqualTo(250)
        assertThat(t.packets).isEqualTo(2)
    }
}

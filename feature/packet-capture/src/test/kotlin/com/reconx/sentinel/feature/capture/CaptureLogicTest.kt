package com.reconx.sentinel.feature.capture

import com.google.common.truth.Truth.assertThat
import java.io.File
import org.junit.Test

class CaptureLogicTest {
    @Test fun `buildV4 produces a valid header and round-trips`() {
        val src = byteArrayOf(10, 0, 0, 1)
        val dst = byteArrayOf(8, 8, 8, 8)
        val udp = ByteArray(8).also { it[4] = 0; it[5] = 8 } // length 8, no payload
        val pkt = IpPacket.buildV4(src, dst, IpPacket.PROTO_UDP, udp)
        val v = IpPacket.parseV4(pkt, pkt.size)!!
        assertThat(v.proto).isEqualTo(IpPacket.PROTO_UDP)
        assertThat(IpPacket.ipToString(v.src)).isEqualTo("10.0.0.1")
        assertThat(IpPacket.ipToString(v.dst)).isEqualTo("8.8.8.8")
        // A correct IPv4 header re-checksums to zero.
        assertThat(IpPacket.checksum(pkt, 0, 20)).isEqualTo(0)
    }

    @Test fun `dns answer is parsed into ip to host`() {
        val m = mutableListOf<Int>()
        // header: id, flags(0x8180), qd=1, an=1, ns=0, ar=0
        m += listOf(0x12,0x34, 0x81,0x80, 0,1, 0,1, 0,0, 0,0)
        // question: 1 'a' 3 'c''o''m' 0  qtype=1 qclass=1
        m += listOf(1,'a'.code, 3,'c'.code,'o'.code,'m'.code, 0, 0,1, 0,1)
        // answer: ptr 0xC00C, type=1, class=1, ttl=0, rdlen=4, rdata 1.2.3.4
        m += listOf(0xC0,0x0C, 0,1, 0,1, 0,0,0,0, 0,4, 1,2,3,4)
        val buf = ByteArray(m.size) { m[it].toByte() }
        val dns = DnsPacketParser.parse(buf, 0, buf.size)!!
        assertThat(dns.queries).contains("a.com")
        assertThat(dns.answers["1.2.3.4"]).isEqualTo("a.com")
    }

    @Test fun `pcap writer emits magic header and records`() {
        val f = File.createTempFile("cap", ".pcap")
        val w = PcapWriter(f)
        w.write(ByteArray(20) { 0x45.toByte() }, 20)
        w.write(ByteArray(40), 40)
        w.close()
        val bytes = f.readBytes()
        assertThat(w.packets).isEqualTo(2)
        // libpcap magic a1 b2 c3 d4 (little-endian on disk)
        assertThat(bytes[0].toInt() and 0xFF).isEqualTo(0xd4)
        assertThat(bytes[1].toInt() and 0xFF).isEqualTo(0xc3)
        // 24-byte global header + 2*(16-byte record header) + 20 + 40 payload
        assertThat(bytes.size).isEqualTo(24 + 16 + 20 + 16 + 40)
        f.delete()
    }
}

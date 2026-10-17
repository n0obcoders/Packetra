package com.reconx.sentinel.feature.capture

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import org.junit.Test

class PacketAdvancedTest {

    private fun clientHello(host: String): ByteArray {
        val hb = host.toByteArray(Charsets.US_ASCII)
        fun u16(o: ByteArrayOutputStream, v: Int) { o.write((v ushr 8) and 0xFF); o.write(v and 0xFF) }
        val sni = ByteArrayOutputStream()
        u16(sni, 3 + hb.size); sni.write(0); u16(sni, hb.size); sni.write(hb)
        val sniBody = sni.toByteArray()
        val ext = ByteArrayOutputStream()
        u16(ext, 0x0000); u16(ext, sniBody.size); ext.write(sniBody)
        val extBytes = ext.toByteArray()
        val hs = ByteArrayOutputStream()
        hs.write(0x03); hs.write(0x03); repeat(32) { hs.write(0) }
        hs.write(0); u16(hs, 2); hs.write(0x00); hs.write(0x2f); hs.write(1); hs.write(0)
        u16(hs, extBytes.size); hs.write(extBytes)
        val hsBody = hs.toByteArray()
        val handshake = ByteArrayOutputStream()
        handshake.write(0x01)
        handshake.write((hsBody.size ushr 16) and 0xFF); u16(handshake, hsBody.size and 0xFFFF)
        handshake.write(hsBody)
        val hsBytes = handshake.toByteArray()
        val rec = ByteArrayOutputStream()
        rec.write(0x16); rec.write(0x03); rec.write(0x01); u16(rec, hsBytes.size); rec.write(hsBytes)
        return rec.toByteArray()
    }

    @Test fun `extracts SNI from a TLS ClientHello`() {
        val b = clientHello("api.example.com")
        assertThat(TlsParser.extractSni(b, 0, b.size)).isEqualTo("api.example.com")
    }

    @Test fun `non-TLS payload yields no SNI`() {
        val b = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        assertThat(TlsParser.extractSni(b, 0, b.size)).isNull()
    }

    @Test fun `parses HTTP host and method`() {
        val b = "GET /path?x=1 HTTP/1.1\r\nHost: www.example.com\r\nUA: t\r\n\r\n".toByteArray()
        val r = HttpParser.parseRequest(b, 0, b.size)!!
        assertThat(r.method).isEqualTo("GET")
        assertThat(r.host).isEqualTo("www.example.com")
        assertThat(r.path).isEqualTo("/path?x=1")
    }

    @Test fun `asn lookup resolves a known cloudflare range`() {
        val geo = AsnLookup().lookup("1.1.1.1")!!
        assertThat(geo.org).isEqualTo("Cloudflare")
        assertThat(AsnLookup().lookup("203.0.113.9")).isNull() // unknown range
    }

    @Test fun `firewall blocks by domain app and ip`() {
        val fw = FirewallRules(blockedApps = setOf(FirewallRules.AppRule("Evil")),
            blockedDomains = setOf("ads.example.com"),
            blockedIps = setOf("9.9.9.9"), enabled = true)
        assertThat(fw.decide("Evil App (com.evil)", null, "1.2.3.4").blocked).isTrue()
        assertThat(fw.decide(null, "x.ads.example.com", "1.2.3.4").blocked).isTrue()
        assertThat(fw.decide(null, "safe.com", "9.9.9.9").blocked).isTrue()
        assertThat(fw.decide(null, "safe.com", "1.2.3.4").blocked).isFalse()
    }

    @Test fun `firewall disabled blocks nothing`() {
        val fw = FirewallRules(blockedIps = setOf("9.9.9.9"), enabled = false)
        assertThat(fw.decide(null, null, "9.9.9.9").blocked).isFalse()
    }

    @Test fun `firewall app rule honours the chosen transport`() {
        val udpOnly = FirewallRules(blockedApps = setOf(FirewallRules.AppRule("tube", FirewallRules.Proto.UDP)),
            enabled = true)
        // UDP (QUIC) is blocked; the same app's TCP is allowed through.
        assertThat(udpOnly.decide("YouTube (com.google.android.youtube)", null, "1.2.3.4", "UDP").blocked).isTrue()
        assertThat(udpOnly.decide("YouTube (com.google.android.youtube)", null, "1.2.3.4", "TCP").blocked).isFalse()
        // BOTH covers either transport.
        val both = FirewallRules(blockedApps = setOf(FirewallRules.AppRule("tube", FirewallRules.Proto.BOTH)),
            enabled = true)
        assertThat(both.decide("YouTube (com.google.android.youtube)", null, "1.2.3.4", "TCP").blocked).isTrue()
        assertThat(both.decide("YouTube (com.google.android.youtube)", null, "1.2.3.4", "UDP").blocked).isTrue()
    }

    @Test fun `firewall parses per-app protocol suffix`() {
        assertThat(FirewallRules.parseAppRule("netflix:udp", FirewallRules.Proto.BOTH))
            .isEqualTo(FirewallRules.AppRule("netflix", FirewallRules.Proto.UDP))
        assertThat(FirewallRules.parseAppRule("com.app", FirewallRules.Proto.TCP))
            .isEqualTo(FirewallRules.AppRule("com.app", FirewallRules.Proto.TCP))
        // A bare colon-less line keeps the default.
        assertThat(FirewallRules.parseAppRule("  Spotify  ", FirewallRules.Proto.BOTH)?.match).isEqualTo("spotify")
    }

    @Test fun `blocklist matches host and parent domain`() {
        val bl = Blocklist()
        bl.loadLines(sequenceOf("0.0.0.0 tracker.bad.com", "# comment", "malware.test"))
        assertThat(bl.isListed("tracker.bad.com")).isTrue()
        assertThat(bl.isListed("sub.malware.test")).isTrue()
        assertThat(bl.isListed("good.com")).isFalse()
        assertThat(bl.size()).isEqualTo(2)
    }

    @Test fun `tracker aggregates per-app usage`() {
        val t = ConnectionTracker(appResolver = { k -> if (k.dstPort == 443) "Browser" else "Mailer" })
        t.record(ConnKey("TCP", "10.0.0.1", 1111, "1.1.1.1", 443), 100, true, null)
        t.record(ConnKey("TCP", "10.0.0.1", 1111, "1.1.1.1", 443), 200, false, null)
        t.record(ConnKey("TCP", "10.0.0.1", 2222, "2.2.2.2", 25), 50, true, null)
        val usage = t.appUsage()
        val browser = usage.first { it.app == "Browser" }
        assertThat(browser.bytesOut).isEqualTo(100)
        assertThat(browser.bytesIn).isEqualTo(200)
        assertThat(usage.map { it.app }).containsExactly("Browser", "Mailer")
    }

    // Builds a minimal IPv4/UDP packet the engine can parse.
    private fun udpPacket(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val l4 = ByteArray(8 + payload.size)
        fun p16(o: Int, v: Int) { l4[o] = (v ushr 8).toByte(); l4[o + 1] = v.toByte() }
        p16(0, sport); p16(2, dport); p16(4, 8 + payload.size); p16(6, 0)
        System.arraycopy(payload, 0, l4, 8, payload.size)
        return IpPacket.buildV4(src, dst, IpPacket.PROTO_UDP, l4)
    }

    @Test fun `firewall drops a blocked app over UDP (e g a VoIP call)`() {
        val tmp = File.createTempFile("tun", ".bin").apply { deleteOnExit() }
        val engine = CaptureEngine(
            tun = TunWriter(FileOutputStream(tmp)),
            socketProtect = SocketProtector { true },
            datagramProtect = DatagramProtector { true },
            pcap = null,
            onDns = {},
            appResolver = { "WhatsApp (com.whatsapp)" },
            firewall = { FirewallRules(blockedApps = setOf(FirewallRules.AppRule("whatsapp")), enabled = true) },
            blocklist = { Blocklist() },
        )
        // A WhatsApp-call-style UDP packet to a Meta media relay; must be blocked.
        val pkt = udpPacket(byteArrayOf(10, 0, 0, 1), byteArrayOf(57, 144.toByte(), 43, 54), 40000, 3478, ByteArray(20))
        engine.onPacket(pkt, pkt.size)
        assertThat(engine.tracker.blockedCount).isEqualTo(1L)
        val flow = engine.tracker.flow(ConnKey("UDP", "10.0.0.1", 40000, "57.144.43.54", 3478))
        assertThat(flow?.blocked).isTrue()
    }

    @Test fun `firewall allows UDP when no rule matches`() {
        val tmp = File.createTempFile("tun", ".bin").apply { deleteOnExit() }
        val engine = CaptureEngine(
            tun = TunWriter(FileOutputStream(tmp)),
            socketProtect = SocketProtector { true },
            datagramProtect = DatagramProtector { true },
            pcap = null,
            onDns = {},
            appResolver = { "WhatsApp (com.whatsapp)" },
            firewall = { FirewallRules(enabled = false) },  // disabled → never blocks
            blocklist = { Blocklist() },
        )
        // Loopback destination so the forwarder's send goes nowhere harmful.
        val pkt = udpPacket(byteArrayOf(10, 0, 0, 1), byteArrayOf(127, 0, 0, 1), 40001, 9, ByteArray(4))
        engine.onPacket(pkt, pkt.size)
        assertThat(engine.tracker.blockedCount).isEqualTo(0L)
    }

    @Test fun `hex dump renders offset hex and ascii columns`() {
        val bytes = "GET /x".toByteArray(Charsets.US_ASCII)
        val dump = HexDump.format(bytes)
        // "GET /x" = 47 45 54 20 2f 78
        assertThat(dump).contains("00000000")
        assertThat(dump).contains("47 45 54 20 2f 78")
        assertThat(dump).contains("GET /x")
    }

    @Test fun `hex dump non-printable bytes become dots and wraps rows`() {
        val bytes = ByteArray(20) { it.toByte() } // 0x00..0x13
        val dump = HexDump.format(bytes)
        assertThat(dump).contains("\n")            // >16 bytes → two rows
        assertThat(dump).contains("00000010")      // second row offset
        assertThat(dump).contains("................") // control bytes render as dots
    }

    @Test fun `tracker samples first packet bytes once per flow`() {
        val tracker = ConnectionTracker()
        val key = ConnKey("TCP", "10.0.0.1", 1111, "1.2.3.4", 443)
        tracker.record(key, 60, true, null)             // flow now exists
        val big = ConnectionTracker.SAMPLE_CAP + 400
        tracker.sample(key, ByteArray(big) { 1 }, big)  // over the cap
        val f1 = tracker.flow(key)!!
        assertThat(f1.sampleLen).isEqualTo(ConnectionTracker.SAMPLE_CAP)
        assertThat(f1.sampleBytes!!.size).isEqualTo(ConnectionTracker.SAMPLE_CAP)
        // second sample must not overwrite the first
        tracker.sample(key, ByteArray(10) { 9 }, 10)
        assertThat(tracker.flow(key)!!.sampleLen).isEqualTo(ConnectionTracker.SAMPLE_CAP)
    }
}

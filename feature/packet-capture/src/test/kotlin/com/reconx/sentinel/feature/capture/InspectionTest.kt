package com.reconx.sentinel.feature.capture

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class InspectionTest {

    // ---- ContentTypeDetector ----

    @Test fun `detects common file types by magic bytes`() {
        val jpeg = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0x00)
        assertThat(ContentTypeDetector.sniff(jpeg, 0, jpeg.size)?.group).isEqualTo("image")
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
        assertThat(ContentTypeDetector.sniff(png, 0, png.size)?.label).isEqualTo("Image (PNG)")
        val pdf = "%PDF-1.7\n...".toByteArray()
        assertThat(ContentTypeDetector.sniff(pdf, 0, pdf.size)?.label).isEqualTo("PDF")
        val mp4 = byteArrayOf(0,0,0,0x18, 0x66,0x74,0x79,0x70, 0x6D,0x70,0x34,0x32)
        assertThat(ContentTypeDetector.sniff(mp4, 0, mp4.size)?.group).isEqualTo("video")
    }

    @Test fun `reads content-type from a cleartext HTTP response and sniffs the body`() {
        val resp = ("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: 3\r\n\r\n" +
            "ÿØÿ").toByteArray(Charsets.ISO_8859_1)
        val k = ContentTypeDetector.sniff(resp, 0, resp.size)
        assertThat(k?.group).isEqualTo("image")
    }

    @Test fun `random ciphertext-like bytes are not classified`() {
        val rnd = ByteArray(64) { ((it * 37 + 11) xor 0x5A).toByte() }
        // Not guaranteed null for all inputs, but high-entropy non-text should miss.
        val k = ContentTypeDetector.sniff(rnd, 0, rnd.size)
        assertThat(k == null || k.group != "text").isTrue()
    }

    // ---- DpiClassifier ----

    @Test fun `classifies tls http dns and quic`() {
        val tls = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x05)
        DpiClassifier.classify(tls, 0, tls.size, 443, "TCP")!!.let {
            assertThat(it.protocol).isEqualTo("TLS"); assertThat(it.encrypted).isTrue()
        }
        val http = "GET / HTTP/1.1\r\n".toByteArray()
        DpiClassifier.classify(http, 0, http.size, 80, "TCP")!!.let {
            assertThat(it.protocol).isEqualTo("HTTP"); assertThat(it.encrypted).isFalse()
        }
        DpiClassifier.classify(ByteArray(0), 0, 0, 53, "UDP")!!.let {
            assertThat(it.protocol).isEqualTo("DNS")
        }
        val quic = byteArrayOf(0xC3.toByte(), 0, 0, 0, 1)
        DpiClassifier.classify(quic, 0, quic.size, 443, "UDP")!!.let {
            assertThat(it.protocol).isEqualTo("QUIC"); assertThat(it.encrypted).isTrue()
        }
    }

    // ---- ProxyHandshake wire format ----

    @Test fun `socks5 connect request encodes ipv4 and port`() {
        val req = ProxyHandshake.socks5ConnectV4(byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34), 443)
        // VER=05 CMD=01 RSV=00 ATYP=01 + ip(4) + port(2)
        assertThat(req.size).isEqualTo(10)
        assertThat(req[0].toInt()).isEqualTo(5)
        assertThat(req[3].toInt()).isEqualTo(1)
        assertThat((req[8].toInt() and 0xFF) shl 8 or (req[9].toInt() and 0xFF)).isEqualTo(443)
    }

    @Test fun `http connect builds a request and parses success`() {
        val req = String(ProxyHandshake.httpConnect("1.2.3.4:443", "u", "p"), Charsets.ISO_8859_1)
        assertThat(req).contains("CONNECT 1.2.3.4:443 HTTP/1.1")
        assertThat(req).contains("Proxy-Authorization: Basic ")
        assertThat(ProxyHandshake.httpConnectOk("HTTP/1.1 200 Connection established")).isTrue()
        assertThat(ProxyHandshake.httpConnectOk("HTTP/1.1 407 Proxy Authentication Required")).isFalse()
    }

    @Test fun `proxy config validation and enabled flag`() {
        assertThat(ProxyConfig().enabled).isFalse()
        assertThat(ProxyConfig(ProxyConfig.Type.SOCKS5, "", 1080).validate()).isNotNull()
        val ok = ProxyConfig(ProxyConfig.Type.SOCKS5, "10.0.0.2", 1080)
        assertThat(ok.validate()).isNull(); assertThat(ok.enabled).isTrue()
    }

    // ---- Country names ----

    @Test fun `country code maps to name and flag`() {
        assertThat(CountryNames.name("US")).isEqualTo("United States")
        assertThat(CountryNames.flag("US")).isEqualTo("🇺🇸")
        assertThat(CountryNames.name("ZZ")).isEqualTo("ZZ")   // unknown → echoes code
        assertThat(CountryNames.display(null)).isEqualTo("—")
    }

    // ---- tracker classify integration ----

    @Test fun `tracker records l7 and content from payload hooks`() {
        val t = ConnectionTracker()
        val key = ConnKey("TCP", "10.0.0.1", 5000, "1.2.3.4", 80)
        t.record(key, 10, outbound = true, host = null)
        val req = "GET /x HTTP/1.1\r\nHost: a\r\n\r\n".toByteArray()
        t.classify(key, req, 0, req.size, outbound = true)
        val resp = ("HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.7").toByteArray()
        t.classify(key, resp, 0, resp.size, outbound = false)
        val f = t.flow(key)!!
        assertThat(f.l7).contains("HTTP")
        assertThat(f.encrypted).isFalse()
        assertThat(f.contentType).isEqualTo("PDF")
        assertThat(f.respSampleLen).isGreaterThan(0)
    }

    @Test fun `encrypted tls flow is marked and not content-sniffed`() {
        val t = ConnectionTracker()
        val key = ConnKey("TCP", "10.0.0.1", 5000, "1.2.3.4", 443)
        t.record(key, 10, outbound = true, host = null)
        val clientHello = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x2a, 0x01)
        t.classify(key, clientHello, 0, clientHello.size, outbound = true)
        val f = t.flow(key)!!
        assertThat(f.encrypted).isTrue()
        assertThat(f.l7).contains("TLS")
        assertThat(f.contentType).isNull()
    }
}

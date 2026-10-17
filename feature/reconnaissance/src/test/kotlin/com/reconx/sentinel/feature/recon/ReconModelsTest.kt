package com.reconx.sentinel.feature.recon

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ReconModelsTest {
    @Test fun `subdomain keeps source attribution`() {
        val s = Subdomain("a.example.com", "crt.sh")
        assertThat(s.resolved).isFalse()
        assertThat(s.source).isEqualTo("crt.sh")
    }
    @Test fun `summary aggregates sources`() {
        val sum = ReconSummary("example.com",
            listOf(Subdomain("a.example.com","crt.sh"), Subdomain("b.example.com","dns")),
            setOf("crt.sh","dns"))
        assertThat(sum.sources).containsExactly("crt.sh","dns")
    }

    @Test fun `rdap parse extracts registrar, dates, nameservers and status`() {
        val json = """
        {
          "objectClassName": "domain",
          "ldhName": "EXAMPLE.COM",
          "status": ["client transfer prohibited", "server delete prohibited"],
          "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:44Z"}
          ],
          "entities": [
            {"roles": ["registrar"],
             "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]]}
          ],
          "nameservers": [
            {"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"},
            {"objectClassName": "nameserver", "ldhName": "B.IANA-SERVERS.NET"}
          ]
        }
        """.trimIndent()
        val w = RdapClient.parse(json, "example.com")
        assertThat(w.registrar).isEqualTo("RESERVED-Internet Assigned Numbers Authority")
        assertThat(w.registered).isEqualTo("1995-08-14T04:00:00Z")
        assertThat(w.expires).isEqualTo("2026-08-13T04:00:00Z")
        assertThat(w.nameservers).containsExactly("a.iana-servers.net", "b.iana-servers.net")
        assertThat(w.statuses).contains("client transfer prohibited")
    }

    @Test fun `takeover rules match CNAME to service and detect dangling banner`() {
        val s3 = TakeoverRules.serviceForCname("my-bucket.s3.amazonaws.com")
        assertThat(s3).isNotNull()
        assertThat(s3!!.service).isEqualTo("AWS S3")
        assertThat(TakeoverRules.hasDanglingFingerprint(s3, "<Error><Code>NoSuchBucket</Code></Error>")).isTrue()
        assertThat(TakeoverRules.hasDanglingFingerprint(s3, "<html>a real site</html>")).isFalse()
    }

    @Test fun `takeover rules identify github pages and ignore unknown cname`() {
        val gh = TakeoverRules.serviceForCname("user.github.io")
        assertThat(gh?.service).isEqualTo("GitHub Pages")
        assertThat(TakeoverRules.hasDanglingFingerprint(gh!!, "There isn't a GitHub Pages site here")).isTrue()
        assertThat(TakeoverRules.serviceForCname("mail.google.com")).isNull()
        assertThat(TakeoverRules.serviceForCname(null)).isNull()
    }

}

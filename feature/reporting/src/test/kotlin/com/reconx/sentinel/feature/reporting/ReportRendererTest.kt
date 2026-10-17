package com.reconx.sentinel.feature.reporting

import com.google.common.truth.Truth.assertThat
import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import org.junit.Test

class ReportRendererTest {
    private fun report(findings: List<Finding>) = AssessmentReport(
        "Demo Engagement", "ACME Lab", 1_700_000_000_000, listOf("example.com"),
        listOf("203.0.113.0/24"), "Packetra/1.0", findings,
        listOf("Non-root VPN capture only"))

    private val sample = Finding("f1", "HSTS not set", "security_header",
        Severity.MEDIUM, Confidence.CONFIRMED, "https://app.example.com",
        remediation = "Add Strict-Transport-Security")

    @Test fun `json contains finding and summary`() {
        val json = ReportRenderer.toJson(report(listOf(sample)))
        assertThat(json).contains("HSTS not set")
        assertThat(json).contains("\"medium\": 1")
    }
    @Test fun `csv has header and row`() {
        val csv = ReportRenderer.toCsv(report(listOf(sample)))
        assertThat(csv.lines().first()).startsWith("id,title,category")
        assertThat(csv).contains("f1")
    }
    @Test fun `html escapes and sorts by severity`() {
        val html = ReportRenderer.toHtml(report(listOf(sample)))
        assertThat(html).contains("<title>")
        assertThat(html).contains("sev-medium")
    }
    @Test fun `secrets are redacted in report output`() {
        val leaky = sample.copy(remediation = "rotate password:hunter2 now")
        val json = ReportRenderer.toJson(report(listOf(leaky)))
        assertThat(json).doesNotContain("hunter2")
    }
}

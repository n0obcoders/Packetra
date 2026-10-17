package com.reconx.sentinel.feature.reporting

import com.google.common.truth.Truth.assertThat
import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import java.io.File
import org.junit.Test

class ReportStoreTest {
    private fun report(name: String, at: Long) = AssessmentReport(
        engagementName = name, clientLabel = "lab", generatedAtEpochMs = at,
        scopeDomains = listOf("example.com"), scopeCidrs = emptyList(), toolVersion = "test",
        findings = listOf(Finding("f1", "HSTS missing", "header", Severity.MEDIUM,
            Confidence.CONFIRMED, "https://example.com")),
    )

    @Test fun `saves three formats and lists them newest first`() {
        val dir = File.createTempFile("reports", "").apply { delete(); mkdirs() }
        val store = ReportStore(dir)
        store.save(report("First engagement", 1_000L))
        val second = store.save(report("Second engagement", 2_000L))

        assertThat(second.htmlFile.exists()).isTrue()
        assertThat(second.jsonFile.exists()).isTrue()
        assertThat(second.csvFile.exists()).isTrue()
        assertThat(second.htmlFile.readText()).contains("HSTS missing")

        val listed = store.list()
        assertThat(listed).hasSize(2)
        assertThat(listed.first().name).isEqualTo("Second engagement") // newest first
        assertThat(listed.first().findingCount).isEqualTo(1)
    }

    @Test fun `list survives a fresh store instance (persistence) and delete removes`() {
        val dir = File.createTempFile("reports", "").apply { delete(); mkdirs() }
        val saved = ReportStore(dir).save(report("Persisted", 5_000L))
        // new instance reads from disk
        val reloaded = ReportStore(dir).list()
        assertThat(reloaded).hasSize(1)
        assertThat(ReportStore(dir).delete(saved.id)).isTrue()
        assertThat(ReportStore(dir).list()).isEmpty()
    }
}

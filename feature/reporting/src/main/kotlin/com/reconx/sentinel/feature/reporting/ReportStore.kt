package com.reconx.sentinel.feature.reporting

import java.io.File

/**
 * Persists generated assessment reports to disk so they survive app restarts
 * and can be re-opened or shared later. Each report is a timestamped folder
 * holding the rendered JSON, CSV and HTML plus a small meta line for the index.
 *
 * File-based (takes a directory, no Android dependency) so it is unit-testable;
 * the app passes filesDir/reports. PDF is produced on demand by the UI layer
 * (Android print/PdfDocument from the HTML); the durable source of truth here is
 * the machine-readable JSON plus the human-readable HTML.
 */
class ReportStore(private val baseDir: File) {

    data class Saved(
        val id: String,
        val name: String,
        val generatedAtEpochMs: Long,
        val findingCount: Int,
        val dir: File,
    ) {
        val htmlFile: File get() = File(dir, "report.html")
        val jsonFile: File get() = File(dir, "report.json")
        val csvFile: File get() = File(dir, "report.csv")
    }

    fun save(report: AssessmentReport): Saved {
        baseDir.mkdirs()
        val id = "${report.generatedAtEpochMs}-${slug(report.engagementName)}"
        val dir = File(baseDir, id).apply { mkdirs() }
        File(dir, "report.json").writeText(ReportRenderer.toJson(report))
        File(dir, "report.csv").writeText(ReportRenderer.toCsv(report))
        File(dir, "report.html").writeText(ReportRenderer.toHtml(report))
        // meta: name|generatedAt|findingCount  (one line, no JSON parser needed)
        File(dir, "meta").writeText(
            "${report.engagementName}\n${report.generatedAtEpochMs}\n${report.findings.size}"
        )
        return Saved(id, report.engagementName, report.generatedAtEpochMs, report.findings.size, dir)
    }

    fun list(): List<Saved> {
        val dirs = baseDir.listFiles { f -> f.isDirectory } ?: return emptyList()
        return dirs.mapNotNull { dir ->
            val meta = File(dir, "meta").takeIf { it.exists() }?.readLines() ?: return@mapNotNull null
            if (meta.size < 3) return@mapNotNull null
            Saved(dir.name, meta[0], meta[1].toLongOrNull() ?: 0L, meta[2].toIntOrNull() ?: 0, dir)
        }.sortedByDescending { it.generatedAtEpochMs }
    }

    fun delete(id: String): Boolean = File(baseDir, id).deleteRecursively()

    private fun slug(s: String): String =
        s.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').take(40).ifBlank { "report" }
}

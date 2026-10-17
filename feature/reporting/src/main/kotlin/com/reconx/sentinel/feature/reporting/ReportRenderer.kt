package com.reconx.sentinel.feature.reporting

import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.security.Redactor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Renders an [AssessmentReport] to JSON, CSV and HTML. Pure string building so
 * it is fully unit-testable and has no Android dependency. All free-text is run
 * through [Redactor] so no secret can leak into a shared report (spec §14, §17).
 * (PDF export is produced on-device by rendering this HTML to a PrintDocument;
 * see BUILD.md — it needs the Android print framework and is not done here.)
 */
object ReportRenderer {
    private fun ts(ms: Long) =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date(ms))

    fun toJson(r: AssessmentReport): String {
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append(""" "engagement": ${q(r.engagementName)},""").append('\n')
        sb.append(""" "client": ${q(r.clientLabel)},""").append('\n')
        sb.append(""" "generated_at": ${q(ts(r.generatedAtEpochMs))},""").append('\n')
        sb.append(""" "tool_version": ${q(r.toolVersion)},""").append('\n')
        sb.append(""" "scope": {"domains": ${arr(r.scopeDomains)}, "cidrs": ${arr(r.scopeCidrs)}},""").append('\n')
        sb.append(""" "summary": {""")
        sb.append(r.bySeverity().entries.joinToString(", ") { "\"${it.key.name.lowercase()}\": ${it.value}" })
        sb.append("},\n")
        sb.append(""" "findings": [""").append('\n')
        sb.append(r.findings.joinToString(",\n") { findingJson(it) })
        sb.append("\n ],\n")
        sb.append(""" "limitations": ${arr(r.limitations)}""").append('\n')
        sb.append("}\n")
        return sb.toString()
    }

    private fun findingJson(f: Finding): String = buildString {
        append("  {")
        append(""""id": ${q(f.id)}, """)
        append(""""title": ${q(f.title)}, """)
        append(""""category": ${q(f.category)}, """)
        append(""""severity": ${q(f.severity.name)}, """)
        append(""""confidence": ${q(f.confidence.name)}, """)
        append(""""verification": ${q(f.verification.name)}, """)
        append(""""target": ${q(f.target)}, """)
        append(""""source": ${q(f.source)}, """)
        append(""""remediation": ${q(f.remediation)}""")
        append("}")
    }

    fun toCsv(r: AssessmentReport): String {
        val head = "id,title,category,severity,confidence,verification,target,source"
        val rows = r.findings.joinToString("\n") { f ->
            listOf(f.id, f.title, f.category, f.severity.name, f.confidence.name,
                f.verification.name, f.target, f.source).joinToString(",") { csv(it) }
        }
        return "$head\n$rows\n"
    }

    fun toHtml(r: AssessmentReport): String {
        val rows = r.findings.sortedByDescending { it.severity.rank }.joinToString("\n") { f ->
            """<tr class="sev-${f.severity.name.lowercase()}">
               <td>${esc(f.severity.name)}</td><td>${esc(f.confidence.name)}</td>
               <td>${esc(f.title)}</td><td>${esc(f.target)}</td>
               <td>${esc(Redactor.redact(f.remediation))}</td></tr>""".trimIndent()
        }
        val summary = r.bySeverity().entries.joinToString(" · ") { "${it.key.name}: ${it.value}" }
        return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${esc(r.engagementName)} — Packetra report</title>
<style>
 body{font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:2rem;color:#111;background:#fff}
 h1{font-size:1.4rem} .meta{color:#555} table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}
 th{background:#f4f4f6} .sev-critical td:first-child{color:#8b0000;font-weight:700}
 .sev-high td:first-child{color:#c0392b;font-weight:700} .sev-medium td:first-child{color:#b9770e}
 .sev-low td:first-child{color:#2c3e50} .sev-info td:first-child{color:#2471a3}
 footer{margin-top:2rem;color:#777;font-size:.85rem}
</style></head><body>
<h1>${esc(r.engagementName)}</h1>
<p class="meta">Client/Lab: ${esc(r.clientLabel)} · Generated: ${esc(ts(r.generatedAtEpochMs))} · ${esc(r.toolVersion)}</p>
<p class="meta">Scope domains: ${esc(r.scopeDomains.joinToString(", "))}<br>Scope CIDRs: ${esc(r.scopeCidrs.joinToString(", "))}</p>
<p><strong>Summary:</strong> $summary</p>
<table><thead><tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Target</th><th>Remediation</th></tr></thead>
<tbody>
$rows
</tbody></table>
${if (r.limitations.isNotEmpty()) "<h2>Limitations</h2><ul>" + r.limitations.joinToString("") { "<li>${esc(it)}</li>" } + "</ul>" else ""}
<footer>Severity and confidence are reported separately. Results reflect the stated scope and tool version and should be reproduced before action.</footer>
</body></html>"""
    }

    private fun q(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
        .replace("\n", "\\n").let { Redactor.redact(it) } + "\""
    private fun arr(items: List<String>) = "[" + items.joinToString(", ") { q(it) } + "]"
    private fun csv(s: String): String {
        val red = Redactor.redact(s)
        return if (red.any { it == ',' || it == '"' || it == '\n' })
            "\"" + red.replace("\"", "\"\"") + "\"" else red
    }
    private fun esc(s: String) = s.replace("&","&amp;").replace("<","&lt;")
        .replace(">","&gt;").replace("\"","&quot;")
}

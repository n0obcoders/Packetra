package com.reconx.sentinel.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.feature.reporting.AssessmentReport
import com.reconx.sentinel.feature.reporting.ReportStore
import com.reconx.sentinel.ui.SentinelViewModel
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ReportsScreen(vm: SentinelViewModel) {
    val e by vm.engagement.collectAsState()
    val ctx = LocalContext.current
    val store = remember { ReportStore(File(ctx.filesDir, "reports")) }
    var saved by remember { mutableStateOf(store.list()) }
    var status by remember { mutableStateOf("") }
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }

    fun share(file: File, mime: String) {
        runCatching {
            val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", file)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = mime
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            ctx.startActivity(Intent.createChooser(send, "Share report"))
        }.onFailure { status = "Share failed: ${it.message}" }
    }

    ScreenColumn {
        SectionCard("Assessment report") {
            Text("Renders JSON / CSV / HTML and saves them to the device so they persist and " +
                "can be shared. Severity and confidence are separate; secrets are redacted. " +
                "Findings aggregated across modules arrive with the shared job engine; the current " +
                "report captures the engagement header and any findings passed in.",
                style = MaterialTheme.typography.bodySmall)
            Button(onClick = {
                val findings = listOf(
                    Finding("f1", "HSTS not set", "security_header", Severity.MEDIUM,
                        Confidence.CONFIRMED, "https://app.${e.domains.firstOrNull() ?: "example.com"}",
                        remediation = "Add Strict-Transport-Security"))
                val report = AssessmentReport(
                    e.name.ifBlank { "Untitled engagement" }, e.clientLabel, System.currentTimeMillis(),
                    e.domains, e.cidrs, "Packetra/1.0", findings,
                    listOf("Non-root VPN capture only; see COMPATIBILITY.md"))
                val s = store.save(report)
                saved = store.list()
                status = "Saved report (${s.findingCount} finding(s))."
            }) { Text("Generate & save report") }
            if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
        }

        if (saved.isEmpty()) {
            SectionCard("Saved reports") { Text("No reports yet.", style = MaterialTheme.typography.bodySmall) }
        } else {
            saved.forEach { r ->
                SectionCard("${r.name} · ${fmt.format(Date(r.generatedAtEpochMs))}") {
                    Text("${r.findingCount} finding(s)", style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilledTonalButton(onClick = { share(r.htmlFile, "text/html") }) { Text("Share HTML") }
                        OutlinedButton(onClick = { share(r.jsonFile, "application/json") }) { Text("JSON") }
                        OutlinedButton(onClick = { share(r.csvFile, "text/csv") }) { Text("CSV") }
                    }
                    OutlinedButton(onClick = { store.delete(r.id); saved = store.list() }) { Text("Delete") }
                }
            }
        }
    }
}

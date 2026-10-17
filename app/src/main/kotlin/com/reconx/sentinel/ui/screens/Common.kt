package com.reconx.sentinel.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.ui.EngagementState
import com.reconx.sentinel.ui.SentinelViewModel

/**
 * Screen-state that survives navigation. The returned Compose state lives in the
 * ViewModel's cache (which outlives leaving/returning to a screen), so a screen's
 * inputs and results are retained — the user never re-enters a domain or loses a
 * finished result after switching tabs. Key must be unique per field per screen.
 */
@Suppress("UNCHECKED_CAST")
fun <T> vmState(vm: SentinelViewModel, key: String, default: T): MutableState<T> =
    vm.uiCache.getOrPut(key) { mutableStateOf(default) } as MutableState<T>

@Suppress("UNCHECKED_CAST")
fun <T> vmList(vm: SentinelViewModel, key: String): SnapshotStateList<T> =
    vm.uiCache.getOrPut(key) { mutableStateListOf<T>() } as SnapshotStateList<T>

/**
 * Standard scrollable screen body. Wrapped in a [SelectionContainer] so every
 * result rendered on it — findings, DNS/WHOIS, hashes, hex, any text — can be
 * long-pressed and copied. Editable text fields inside manage their own
 * selection and keep working normally.
 */
@Composable
fun ScreenColumn(content: @Composable ColumnScope.() -> Unit) =
    SelectionContainer {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = content,
        )
    }

@Composable
fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) =
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }

/** The scope/authorization banner required on every active screen (spec §3, §13). */
@Composable
fun ScopeBanner(e: EngagementState) {
    val (text, container) = if (!e.hasScope)
        "No targets yet — add hosts in Settings to run active modules. " +
            "Passive recon (OSINT, DNS) works without scope." to MaterialTheme.colorScheme.errorContainer
    else
        "Scope: ${e.domains.size} host(s), ${e.cidrs.size} range(s)" to MaterialTheme.colorScheme.primaryContainer
    Surface(color = container, shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth()) {
        Text(text, Modifier.padding(12.dp), style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
fun Mono(text: String) =
    Text(text, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)

/**
 * A results card whose rows can be copied to the clipboard. Shows a copy button
 * in the header that puts every line on the clipboard as newline-joined text.
 */
@Composable
fun CopyableResults(title: String, lines: List<String>) {
    val clipboard = LocalClipboardManager.current
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                TextButton(onClick = { clipboard.setText(AnnotatedString(lines.joinToString("\n"))) }) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy all",
                        modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp)); Text("Copy")
                }
            }
            lines.forEach { Mono(it) }
        }
    }
}

@Composable
fun Placeholder(title: String, body: String) = ScreenColumn {
    SectionCard(title) { Text(body, style = MaterialTheme.typography.bodyMedium) }
}

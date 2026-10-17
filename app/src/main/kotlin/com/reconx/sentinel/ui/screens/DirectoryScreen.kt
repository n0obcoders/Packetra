package com.reconx.sentinel.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.feature.web.DirectoryScanner
import com.reconx.sentinel.ui.SentinelViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun DirectoryScreen(vm: SentinelViewModel) {
    val e by vm.engagement.collectAsState()
    val scan by vm.dirScan.collectAsState()
    val ctx = LocalContext.current
    // Inputs persist across navigation via the ViewModel cache (results already
    // persist via vm.dirScan), so returning to this screen keeps everything.
    var url by vmState(vm, "dir.url", "https://")
    var exts by vmState(vm, "dir.exts", "")
    var cap by vmState(vm, "dir.cap", "5000")
    var loadStatus by vmState(vm, "dir.loadStatus", "")

    // Built-in quick list ships with the app; large lists (DirBuster
    // directory-list-2.3-medium, SecLists, etc.) are loaded by the operator at
    // scan time so the choice of wordlist — and the authorization it implies —
    // stays with the person running the engagement.
    val builtIn = remember {
        runCatching { ctx.assets.open("wordlists/common.txt").bufferedReader().use { it.readLines() } }
            .getOrDefault(emptyList())
            .map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
    }
    var loaded by vmState<List<String>>(vm, "dir.loaded", emptyList())
    var loadedName by vmState<String?>(vm, "dir.loadedName", null)
    var useLoaded by vmState(vm, "dir.useLoaded", false)

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) vm.vmLaunch {
            loadStatus = "Loading wordlist…"
            val lines = withContext(Dispatchers.IO) {
                runCatching {
                    ctx.contentResolver.openInputStream(uri)?.bufferedReader()?.use { r ->
                        r.lineSequence().map { it.trim() }
                            .filter { it.isNotEmpty() && !it.startsWith("#") }
                            .toList()
                    } ?: emptyList()
                }.getOrDefault(emptyList())
            }
            loaded = lines
            loadedName = uri.lastPathSegment?.substringAfterLast('/')
            useLoaded = lines.isNotEmpty()
            loadStatus = if (lines.isEmpty()) "Could not read that file." else "Loaded ${lines.size} entries."
        }
    }

    val active = if (useLoaded) loaded else builtIn
    val capN = cap.toIntOrNull()?.coerceAtLeast(1) ?: active.size
    val words = remember(active, capN) { active.take(capN) }

    ScreenColumn {
        ScopeBanner(e)
        SectionCard("Content discovery (DirBuster-style)") {
            Text("GET-only, soft-404 filtered, scope-gated, bounded concurrency. Runs in the " +
                "background — you can leave this screen and come back; the app stays responsive.",
                style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(url, { url = it }, label = { Text("Authorized base URL") },
                singleLine = true, modifier = Modifier.fillMaxWidth(), enabled = !scan.running)
            OutlinedTextField(exts, { exts = it }, label = { Text("Extensions (optional, e.g. php,bak,zip)") },
                singleLine = true, modifier = Modifier.fillMaxWidth(), enabled = !scan.running)

            Row(verticalAlignment = Alignment.CenterVertically) {
                FilterChip(selected = !useLoaded, onClick = { useLoaded = false }, enabled = !scan.running,
                    label = { Text("Built-in (${builtIn.size})") })
                Spacer(Modifier.width(8.dp))
                FilterChip(selected = useLoaded, enabled = loaded.isNotEmpty() && !scan.running,
                    onClick = { useLoaded = true },
                    label = { Text(loadedName?.let { "$it (${loaded.size})" } ?: "Loaded file") })
            }
            OutlinedButton(onClick = { picker.launch(arrayOf("text/plain", "*/*")) }, enabled = !scan.running) {
                Text("Load wordlist file…")
            }
            OutlinedTextField(cap, { cap = it.filter { c -> c.isDigit() } },
                label = { Text("Max paths this run") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(), enabled = !scan.running)
            Text("Will probe ${words.size} path(s)" +
                if (active.size > words.size) " of ${active.size} (capped)" else "",
                style = MaterialTheme.typography.bodySmall)
            if (loadStatus.isNotBlank()) Text(loadStatus, style = MaterialTheme.typography.bodySmall)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(enabled = !scan.running && url.length > 8 && words.isNotEmpty(), onClick = {
                    val extList = buildList { add(""); addAll(exts.split(',').map { it.trim() }.filter { it.isNotEmpty() }) }
                    vm.runDirectoryScan(DirectoryScanner.Config(url.trim(), words, extList))
                }) { Text(if (scan.running) "Scanning…" else "Start") }
                if (scan.running) OutlinedButton(onClick = { vm.cancelDirectoryScan() }) { Text("Stop") }
            }
            if (scan.running) LinearProgressIndicator(progress = { scan.progress }, modifier = Modifier.fillMaxWidth())
            if (scan.status.isNotBlank()) Text(scan.status, style = MaterialTheme.typography.bodySmall)
        }
        if (scan.hits.isNotEmpty()) CopyableResults("Found (${scan.hits.size})", scan.hits)
    }
}

package com.reconx.sentinel.ui.screens

import android.app.Activity
import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.provider.MediaStore
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.di.SettingsRepository
import com.reconx.sentinel.feature.capture.CaptureController
import com.reconx.sentinel.feature.capture.ConnectionFlow
import com.reconx.sentinel.feature.capture.CountryNames
import com.reconx.sentinel.feature.capture.FirewallRules
import com.reconx.sentinel.feature.capture.HarExport
import com.reconx.sentinel.feature.capture.HexDump
import com.reconx.sentinel.feature.capture.ProxyConfig
import com.reconx.sentinel.feature.capture.SentinelVpnService
import java.io.File

private enum class PacketTab(val label: String) {
    CONNECTIONS("Connections"), APPS("Apps"), FIREWALL("Firewall"), PROXY("Proxy"), EXPORT("Export")
}

@Composable
fun PacketScreen() {
    val ctx = LocalContext.current
    val running by CaptureController.running.collectAsState()
    val stats by CaptureController.stats.collectAsState()
    var note by remember { mutableStateOf("") }
    var tab by remember { mutableStateOf(PacketTab.CONNECTIONS) }
    var appFilter by remember { mutableStateOf<String?>(null) }

    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == Activity.RESULT_OK) {
            ContextCompat_startForegroundService(ctx, Intent(ctx, SentinelVpnService::class.java))
            note = "Capture started."
        } else note = "VPN permission was not granted."
    }

    // Once a capture has recorded a set of packets, show a small prompt (for ~5s)
    // telling the user to inspect exported packets with n3-editor. Armed on each
    // new capture run, fired once when the first packets land.
    var hintArmed by remember { mutableStateOf(false) }
    var showN3Hint by remember { mutableStateOf(false) }
    LaunchedEffect(running) { if (running) { hintArmed = true; showN3Hint = false } }
    LaunchedEffect(running, stats.packets) {
        if (running && hintArmed && stats.packets > 0) {
            hintArmed = false
            showN3Hint = true
            kotlinx.coroutines.delay(5000)
            showN3Hint = false
        }
    }

    Box(Modifier.fillMaxSize()) {
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Captures THIS device's own traffic via a local VpnService (non-root). HTTPS/QUIC " +
                "payloads stay encrypted — flows, DNS, SNI/Host, per-app usage, geo/ASN, protocol (DPI) and " +
                "any cleartext content type are recorded; a PCAPng is written for Wireshark.",
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(enabled = !running, onClick = {
                    val prep = VpnService.prepare(ctx)
                    if (prep != null) vpnLauncher.launch(prep)
                    else { ContextCompat_startForegroundService(ctx, Intent(ctx, SentinelVpnService::class.java)); note = "Capture started." }
                }) { Text("Start capture") }
                OutlinedButton(enabled = running, onClick = {
                    ctx.startService(Intent(ctx, SentinelVpnService::class.java).setAction(SentinelVpnService.ACTION_STOP))
                    note = "Capture stopped."
                }) { Text("Stop") }
            }
            Mono("State: ${if (running) "capturing" else "idle"}   Flows: ${stats.flows}   " +
                "Pkts: ${stats.packets}   Blocked: ${stats.blocked}" +
                if (stats.pcapOverIpClients > 0) "   Wireshark: ${stats.pcapOverIpClients}" else "")
            if (note.isNotBlank()) Text(note, style = MaterialTheme.typography.bodySmall)
        }

        ScrollableTabRow(selectedTabIndex = tab.ordinal, edgePadding = 0.dp) {
            PacketTab.entries.forEach { t ->
                Tab(selected = tab == t, onClick = { tab = t; if (t != PacketTab.CONNECTIONS) appFilter = null },
                    text = { Text(t.label) })
            }
        }

        // Each tab owns a LazyColumn so only the rows actually on screen compose and
        // lay out. Under a live capture the connection/app lists can hold hundreds of
        // entries and refresh every second; a lazy list keeps that smooth where the
        // previous non-lazy, fully-selectable column rebuilt every row each tick.
        Box(Modifier.weight(1f).fillMaxWidth()) {
            when (tab) {
                PacketTab.CONNECTIONS -> ConnectionsTab(appFilter) { appFilter = null }
                PacketTab.APPS -> AppsTab { app -> appFilter = app; tab = PacketTab.CONNECTIONS }
                PacketTab.FIREWALL -> FirewallTab()
                PacketTab.PROXY -> ProxyTab { note = it }
                PacketTab.EXPORT -> ExportTab { note = it }
            }
        }
    }

        if (showN3Hint) N3EditorHint(Modifier.align(Alignment.BottomCenter)) { showN3Hint = false }
    }
}

/** Transient prompt: inspect exported packets with n3-editor. Tap to open, or the ✕. */
@Composable
private fun N3EditorHint(modifier: Modifier = Modifier, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    ElevatedCard(modifier.padding(16.dp).fillMaxWidth()) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Column(Modifier.weight(1f)) {
                Text("Packets captured", style = MaterialTheme.typography.titleSmall)
                Text("To read your exported packets, use n3-editor — an advanced pcap-reader " +
                    "notepad (github.com/n3-editor).", style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = {
                runCatching {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/n3-editor"))
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }
            }) { Text("Open") }
            IconButton(onClick = onDismiss) { Icon(Icons.Filled.Clear, "dismiss") }
        }
    }
}

/** Compatibility wrapper — foreground services must be started the O+ way on O+. */
private fun ContextCompat_startForegroundService(ctx: Context, intent: Intent) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(intent)
    else ctx.startService(intent)
}

// ---------- Connections ----------

private enum class ProtoFilter(val label: String) { ALL("All"), TCP("TCP"), UDP("UDP") }

@Composable
private fun ConnectionsTab(appFilter: String?, onClearFilter: () -> Unit) {
    val flows by CaptureController.flows.collectAsState()
    val dns by CaptureController.dns.collectAsState()
    var selected by remember { mutableStateOf<ConnectionFlow?>(null) }

    // Combined filter: one query box (matches IP, host/SNI, app name, or a port
    // number) plus a transport toggle — so "filter by IP, then TCP/UDP, or port"
    // is a single control.
    var query by remember { mutableStateOf("") }
    var proto by remember { mutableStateOf(ProtoFilter.ALL) }

    val shown = remember(flows, appFilter, query, proto) {
        val q = query.trim().lowercase()
        val qPort = q.toIntOrNull()
        flows.filter { f ->
            (appFilter == null || (f.appLabel ?: "unknown") == appFilter) &&
                (proto == ProtoFilter.ALL || f.protocol.equals(proto.name, ignoreCase = true)) &&
                matchesQuery(f, q, qPort)
        }
    }

    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 16.dp),
    ) {
        item {
            OutlinedTextField(
                value = query, onValueChange = { query = it },
                label = { Text("Filter by IP, host, app or port") },
                singleLine = true, modifier = Modifier.fillMaxWidth(),
                leadingIcon = { Icon(Icons.Filled.Search, null) },
                trailingIcon = {
                    if (query.isNotEmpty()) IconButton(onClick = { query = "" }) {
                        Icon(Icons.Filled.Clear, "clear")
                    }
                },
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    capitalization = KeyboardCapitalization.None),
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically) {
                ProtoFilter.entries.forEach { p ->
                    FilterChip(selected = proto == p, onClick = { proto = p }, label = { Text(p.label) })
                }
                if (appFilter != null) AssistChip(onClick = onClearFilter,
                    label = { Text("App: ${displayName(appFilter)}  ✕") })
            }
        }

        item {
            SectionCard("Hosts from DNS / TLS / HTTP (${dns.size} DNS)") {
                Text("Hostnames are recovered from DNS answers, TLS ClientHello SNI and cleartext " +
                    "HTTP Host headers — no decryption.", style = MaterialTheme.typography.bodySmall)
                dns.take(20).forEach { Mono(it.name) }
            }
        }

        if (shown.isEmpty()) {
            item {
                SectionCard(if (flows.isEmpty()) "Connections" else "Connections (0 match)") {
                    Text(
                        if (flows.isEmpty())
                            "No connections yet. Start a capture and use the network, then tap a row to inspect it."
                        else "No connections match this filter.",
                        style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            item {
                Text("Connections (${shown.size}${if (shown.size != flows.size) " of ${flows.size}" else ""})",
                    style = MaterialTheme.typography.titleMedium)
            }
            items(shown, key = { it.protocol + it.srcPort + it.destIp + it.destPort }) { f ->
                ConnectionRow(f) { selected = f }
            }
        }
    }

    selected?.let { ConnectionDetailDialog(it) { selected = null } }
}

/** Does the flow match the combined query (blank matches all)? */
private fun matchesQuery(f: ConnectionFlow, q: String, qPort: Int?): Boolean {
    if (q.isEmpty()) return true
    if (qPort != null && f.destPort == qPort) return true
    if (f.destIp.contains(q)) return true
    if (f.protocol.equals(q, ignoreCase = true)) return true
    val host = (f.host ?: f.sni ?: f.httpHost)?.lowercase()
    if (host != null && host.contains(q)) return true
    val app = f.appLabel?.lowercase()
    return app != null && app.contains(q)
}

@Composable
private fun ConnectionRow(f: ConnectionFlow, onClick: () -> Unit) {
    val host = f.host ?: f.sni ?: f.httpHost
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        AppIcon(f.appLabel, 40.dp)
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(displayName(f.appLabel) ?: "Unknown", style = MaterialTheme.typography.bodyMedium)
                if (f.encrypted) Icon(Icons.Filled.Lock, "encrypted",
                    tint = MaterialTheme.colorScheme.outline, modifier = Modifier.size(14.dp))
                if (f.blocked) Icon(Icons.Filled.Block, "blocked",
                    tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(16.dp))
                if (f.malicious) Icon(Icons.Filled.Warning, "malicious",
                    tint = Color(0xFFB00020), modifier = Modifier.size(16.dp))
            }
            Mono("${f.protocol} ${host ?: f.destIp}:${f.destPort}")
            val proto = listOfNotNull(f.l7, if (f.encrypted) "encrypted" else f.contentType).joinToString("  ·  ")
            if (proto.isNotEmpty()) Text(proto, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary)
            val loc = locationLine(f)
            if (loc.isNotEmpty()) Text(loc, style = MaterialTheme.typography.labelSmall)
        }
        Column(horizontalAlignment = Alignment.End) {
            Text("↑${human(f.bytesOut)}", style = MaterialTheme.typography.labelSmall)
            Text("↓${human(f.bytesIn)}", style = MaterialTheme.typography.labelSmall)
        }
    }
    HorizontalDivider()
}

@Composable
private fun ConnectionDetailDialog(f: ConnectionFlow, onDismiss: () -> Unit) {
    val host = f.host ?: f.sni ?: f.httpHost
    val ctx = LocalContext.current
    var action by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        dismissButton = {
            TextButton(onClick = { action = openApp(ctx, f.appLabel) }) {
                Icon(Icons.Filled.OpenInNew, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp)); Text("Open app")
            }
        },
        title = {
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                AppIcon(f.appLabel, 32.dp)
                Text(displayName(f.appLabel) ?: "Unknown app")
            }
        },
        text = {
            SelectionContainer {
                Column(Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    detailRow("Protocol", "${f.protocol}  (src port ${f.srcPort})")
                    f.l7?.let { detailRow("App layer", it) }
                    detailRow("Encrypted", if (f.encrypted) "yes — payload is ciphertext, not inspectable" else "no")
                    detailRow("Carrying", f.contentType
                        ?: if (f.encrypted) "encrypted (no cleartext content)" else "— (not yet determined)")
                    detailRow("Remote", "${f.destIp}:${f.destPort}")
                    host?.let { detailRow("Host", it) }
                    f.sni?.let { detailRow("TLS SNI", it) }
                    f.httpHost?.let { detailRow("HTTP Host", it) }
                    if (f.httpMethod != null) detailRow("HTTP", "${f.httpMethod} ${f.httpPath ?: "/"}")
                    f.asn?.let { detailRow("ASN", it) }
                    f.org?.let { detailRow("Network", it) }
                    detailRow("Location", CountryNames.display(f.country))
                    detailRow("Packets", "${f.packets}")
                    detailRow("Sent", human(f.bytesOut))
                    detailRow("Received", human(f.bytesIn))
                    if (f.blocked) detailRow("State", "BLOCKED by firewall")
                    if (f.malicious) detailRow("Flag", "on malware/tracker blocklist")
                    if (action.isNotBlank()) Text(action, style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary)

                    Spacer(Modifier.height(8.dp))
                    PayloadBlock("Request — first packet", f.sampleBytes, f.sampleLen)
                    if (f.respSampleBytes != null && f.respSampleLen > 0) {
                        Spacer(Modifier.height(8.dp))
                        PayloadBlock("Response — first inbound payload", f.respSampleBytes, f.respSampleLen)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text("Bytes are as seen on the wire — never decrypted. A TLS/QUIC flow shows " +
                        "ciphertext; cleartext (HTTP, DNS, etc.) is readable and its content type is detected " +
                        "above. Full capture: export the PCAPng and open it in Wireshark.",
                        style = MaterialTheme.typography.labelSmall)
                }
            }
        },
    )
}

/** Hex + printable-ASCII view of a captured payload sample, with a copy button. */
@Composable
private fun PayloadBlock(label: String, bytes: ByteArray?, len: Int) {
    val clipboard = LocalClipboardManager.current
    if (bytes == null || len <= 0) {
        Text("$label: no bytes sampled for this flow yet.", style = MaterialTheme.typography.labelSmall)
        return
    }
    val hex = remember(bytes, len) { HexDump.format(bytes, len) }
    val text = remember(bytes, len) { printable(bytes, len) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("$label ($len bytes)", style = MaterialTheme.typography.labelMedium, modifier = Modifier.weight(1f))
        TextButton(onClick = { clipboard.setText(AnnotatedString(hex)) }) {
            Icon(Icons.Filled.ContentCopy, "copy hex", modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(2.dp)); Text("Hex")
        }
    }
    Surface(color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(6.dp), modifier = Modifier.fillMaxWidth()) {
        Text(hex, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.horizontalScroll(rememberScrollState()).padding(8.dp))
    }
    if (text.isNotBlank()) {
        Spacer(Modifier.height(4.dp))
        Text("Readable text", style = MaterialTheme.typography.labelMedium)
        Surface(color = MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(6.dp), modifier = Modifier.fillMaxWidth()) {
            Text(text.take(2000), fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(8.dp))
        }
    }
}

@Composable
private fun detailRow(k: String, v: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(k, style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(92.dp))
        Text(v, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.weight(1f))
    }
}

// ---------- Apps ----------

@Composable
private fun AppsTab(onOpenApp: (String) -> Unit) {
    val usage by CaptureController.appUsage.collectAsState()
    val ctx = LocalContext.current
    var note by remember { mutableStateOf("") }
    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 16.dp),
    ) {
        item {
            SectionCard("Data usage per app") {
                Text("Every app (system and user) that generated traffic this capture, attributed by " +
                    "connection owner (Android 10+). Tap a row to see only its connections, or the launch " +
                    "icon to open the app (or its App info when it has no launcher).",
                    style = MaterialTheme.typography.bodySmall)
                if (note.isNotBlank()) Text(note, style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary)
            }
        }
        if (usage.isEmpty()) {
            item { SectionCard("Apps") { Text("No data yet.", style = MaterialTheme.typography.bodySmall) } }
        } else {
            items(usage, key = { it.app }) { u ->
                ElevatedCard(Modifier.fillMaxWidth()) {
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpenApp(u.app) }.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        AppIcon(u.app, 40.dp)
                        Column(Modifier.weight(1f)) {
                            Text("${displayName(u.app) ?: "Unknown"} (${u.connections})",
                                style = MaterialTheme.typography.bodyMedium)
                            Text("↓${human(u.bytesIn)} received  ·  ↑${human(u.bytesOut)} sent  ·  ${u.packets} pkts",
                                style = MaterialTheme.typography.labelSmall)
                        }
                        IconButton(onClick = { note = openApp(ctx, u.app) }) {
                            Icon(Icons.Filled.OpenInNew, "open app")
                        }
                        Text(human(u.bytesIn + u.bytesOut), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
    }
}

// ---------- Firewall ----------

@Composable
private fun FirewallTab() {
    val fw by CaptureController.firewall.collectAsState()
    val blocklistCount by CaptureController.blocklistCount.collectAsState()
    val ctx = LocalContext.current
    val store = remember { SettingsRepository(ctx) }
    fun applyFirewall(r: FirewallRules) { CaptureController.setFirewall(r); runCatching { store.saveFirewall(r) } }
    var defProto by remember { mutableStateOf(FirewallRules.Proto.BOTH) }
    var apps by remember { mutableStateOf(appRulesToText(fw.blockedApps)) }
    var domains by remember { mutableStateOf(fw.blockedDomains.joinToString("\n")) }
    var ips by remember { mutableStateOf(fw.blockedIps.joinToString("\n")) }
    var status by remember { mutableStateOf("") }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            val n = runCatching {
                ctx.contentResolver.openInputStream(uri)?.bufferedReader()?.use { r ->
                    CaptureController.loadBlocklist(r.readLines().asSequence())
                    CaptureController.blocklistCount.value
                } ?: 0
            }.getOrDefault(0)
            status = if (n > 0) "Loaded $n blocklist entries." else "Could not read that file."
        }
    }

    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 16.dp),
    ) {
        item {
            SectionCard("Firewall") {
                Text("Block connections per app, domain or IP. Rules apply live: matching traffic is dropped " +
                    "and an in-progress flow is cut. Multiple apps: one per line. For a voice/video call " +
                    "(e.g. WhatsApp, which uses UDP to many IPs) block by APP name, not IP.",
                    style = MaterialTheme.typography.bodySmall)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = fw.enabled, onCheckedChange = {
                        applyFirewall(currentRules(it, apps, domains, ips, defProto))
                    })
                    Spacer(Modifier.width(8.dp)); Text(if (fw.enabled) "Enabled" else "Disabled")
                }

                Text("Block which transport for apps:", style = MaterialTheme.typography.labelMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FirewallRules.Proto.entries.forEach { p ->
                        FilterChip(selected = defProto == p, onClick = { defProto = p },
                            label = { Text(if (p == FirewallRules.Proto.BOTH) "TCP + UDP" else p.name) })
                    }
                }
                Text("This is the default for each app line. Override per app with a suffix, e.g. " +
                    "\"youtube:udp\" (block only its UDP/QUIC) or \"dropbox:tcp\".",
                    style = MaterialTheme.typography.labelSmall)

                OutlinedTextField(apps, { apps = it }, label = { Text("Block apps (one per line, name contains)") },
                    modifier = Modifier.fillMaxWidth(), minLines = 2, maxLines = 6,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.None))
                OutlinedTextField(domains, { domains = it }, label = { Text("Block domains") },
                    modifier = Modifier.fillMaxWidth(), minLines = 1, maxLines = 4,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.None))
                OutlinedTextField(ips, { ips = it }, label = { Text("Block IPs") },
                    modifier = Modifier.fillMaxWidth(), minLines = 1, maxLines = 4,
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.None, keyboardType = KeyboardType.Number))
                Button(onClick = {
                    applyFirewall(currentRules(fw.enabled, apps, domains, ips, defProto))
                    status = "Firewall rules applied."
                }) { Text("Apply rules") }
                if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
            }
        }

        item {
            SectionCard("Malware / tracker blocklist ($blocklistCount loaded)") {
                Text("Load a hosts-file or domain list (e.g. StevenBlack, a tracker list). Connections to a " +
                    "listed host are flagged in the Connections tab; enable the firewall to also block them.",
                    style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { runCatching { picker.launch(arrayOf("text/plain", "*/*")) } }) { Text("Load list") }
                    OutlinedButton(enabled = blocklistCount > 0, onClick = {
                        CaptureController.clearBlocklist(); status = "Blocklist cleared."
                    }) { Text("Clear") }
                }
            }
        }
    }
}

private fun currentRules(enabled: Boolean, apps: String, domains: String, ips: String, defProto: FirewallRules.Proto) =
    FirewallRules(
        blockedApps = parseAppRules(apps, defProto),
        blockedDomains = splitLines(domains),
        blockedIps = splitLines(ips),
        enabled = enabled,
    )

private fun parseAppRules(s: String, def: FirewallRules.Proto): Set<FirewallRules.AppRule> =
    s.split('\n', ',').mapNotNull { FirewallRules.parseAppRule(it, def) }.toSet()

private fun appRulesToText(rules: Set<FirewallRules.AppRule>): String =
    rules.joinToString("\n") {
        if (it.proto == FirewallRules.Proto.BOTH) it.match else "${it.match}:${it.proto.name.lowercase()}"
    }

private fun splitLines(s: String): Set<String> =
    s.split('\n', ',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()

// ---------- Proxy ----------

@Composable
private fun ProxyTab(onNote: (String) -> Unit) {
    val ctx = LocalContext.current
    val store = remember { SettingsRepository(ctx) }
    val cfg by CaptureController.proxy.collectAsState()
    var type by remember { mutableStateOf(cfg.type) }
    var host by remember { mutableStateOf(cfg.host) }
    var port by remember { mutableStateOf(if (cfg.port > 0) cfg.port.toString() else "") }
    var user by remember { mutableStateOf(cfg.username ?: "") }
    var pass by remember { mutableStateOf(cfg.password ?: "") }
    var status by remember { mutableStateOf("") }

    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 16.dp),
    ) {
        item {
            SectionCard("Upstream proxy (route captured TCP through a server)") {
                Text("Send captured TCP connections through your own SOCKS5 or HTTP proxy / VPN service while " +
                    "still capturing and analysing them locally. This is routing only — nothing is decrypted; " +
                    "HTTPS stays end-to-end encrypted through the proxy. UDP (DNS, QUIC) is sent directly so it " +
                    "keeps working. Takes effect on new connections.",
                    style = MaterialTheme.typography.bodySmall)

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ProxyConfig.Type.entries.forEach { t ->
                        FilterChip(selected = type == t, onClick = { type = t },
                            label = { Text(if (t == ProxyConfig.Type.NONE) "Off" else t.name) })
                    }
                }

                if (type != ProxyConfig.Type.NONE) {
                    OutlinedTextField(host, { host = it }, label = { Text("Proxy host / IP") },
                        singleLine = true, modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.None))
                    OutlinedTextField(port, { port = it.filter(Char::isDigit).take(5) }, label = { Text("Port") },
                        singleLine = true, modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = KeyboardType.Number))
                    OutlinedTextField(user, { user = it }, label = { Text("Username (optional)") },
                        singleLine = true, modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.None))
                    OutlinedTextField(pass, { pass = it }, label = { Text("Password (optional)") },
                        singleLine = true, modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(capitalization = KeyboardCapitalization.None))
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        val c = ProxyConfig(type, host.trim(), port.toIntOrNull() ?: 0,
                            user.trim().ifBlank { null }, pass.ifBlank { null })
                        val err = c.validate()
                        if (err != null) { status = err } else {
                            CaptureController.setProxy(c); runCatching { store.saveProxy(c) }
                            status = if (c.enabled) "Proxy set: ${c.type} ${c.host}:${c.port} (applies to new TCP connections)."
                            else "Proxy disabled — connecting directly."
                            onNote(status)
                        }
                    }) { Text("Apply proxy") }
                    OutlinedButton(onClick = {
                        type = ProxyConfig.Type.NONE
                        val off = ProxyConfig(); CaptureController.setProxy(off); runCatching { store.saveProxy(off) }
                        status = "Proxy disabled."
                    }) { Text("Disable") }
                }
                if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
            }
        }

        item {
            SectionCard("How it relates to decryption") {
                Text("A proxy forwards your encrypted bytes; it does not and cannot reveal HTTPS contents here. " +
                    "Seeing inside your own HTTPS requires a consensual TLS-intercepting proxy with a CA you " +
                    "install on your own device (e.g. mitmproxy or PCAPdroid's mitm add-on) — a separate tool " +
                    "this passive analyzer deliberately does not implement.",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

// ---------- Export ----------

@Composable
private fun ExportTab(onNote: (String) -> Unit) {
    val ctx = LocalContext.current
    val pcapOverIp by CaptureController.pcapOverIp.collectAsState()
    val flows by CaptureController.flows.collectAsState()

    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 16.dp),
    ) {
        item {
            SectionCard("PCAPng / PCAP file") {
                Text("Every capture is written to a PCAPng file (modern Wireshark format, preserves " +
                    "per-packet metadata). Export it to your Downloads folder.",
                    style = MaterialTheme.typography.bodySmall)
                Button(enabled = CaptureController.lastPcapPath != null,
                    onClick = { onNote(exportCapture(ctx)) }) { Text("Export PCAPng to Downloads") }
            }
        }

        item {
            SectionCard("Read exported packets — n3-editor") {
                Text("Once exported, your PCAP holds the packets worth keeping. Open it in " +
                    "n3-editor — an advanced pcap-reader notepad — to read every packet and what " +
                    "it contains, or in Wireshark.", style = MaterialTheme.typography.bodySmall)
                Button(onClick = {
                    runCatching {
                        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/n3-editor"))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                }) { Text("Open n3-editor (github.com/n3-editor)") }
            }
        }

        item {
            SectionCard("PCAP-over-IP (live to Wireshark)") {
                Text("Streams packets over TCP so a desktop Wireshark can read the capture in real time. " +
                    "On the desktop run 'nc <device-ip> ${CaptureController.pcapOverIpPort} | wireshark -k -i -', " +
                    "or add a Pipe in Wireshark. Takes effect on the next Start capture.",
                    style = MaterialTheme.typography.bodySmall)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = pcapOverIp, onCheckedChange = { CaptureController.setPcapOverIp(it) })
                    Spacer(Modifier.width(8.dp))
                    Text(if (pcapOverIp) "On — port ${CaptureController.pcapOverIpPort}" else "Off")
                }
            }
        }

        item {
            SectionCard("HAR (cleartext HTTP only)") {
                Text("Exports the plaintext HTTP requests observed (method, URL, host, byte counts) as a " +
                    "HAR 1.2 file. HTTPS/TLS is encrypted and is NOT decrypted, so it does not appear here " +
                    "and there are no request/response bodies — this is a passive capture, not a proxy.",
                    style = MaterialTheme.typography.bodySmall)
                Button(onClick = { onNote(exportHar(ctx, flows)) }) { Text("Export HAR to Downloads") }
            }
        }

        item {
            SectionCard("What this does NOT do (honest limits)") {
                Text("No HTTPS/TLS decryption, no SSLKEYLOGFILE, no CA installation, no man-in-the-middle. " +
                    "Full HTTPS inspection would require installing a trusted CA and a native TLS proxy, which " +
                    "this app deliberately does not do. Capture is IPv4, this device's own traffic only.",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

// ---------- icon + helpers ----------

/** The app label is "Display Name (com.pkg.id)"; the package is in the parens. */
private fun pkgOf(label: String?): String? {
    if (label == null) return null
    val m = Regex("\\(([a-zA-Z][a-zA-Z0-9_.]+\\.[a-zA-Z0-9_.]+)\\)").find(label)
    return m?.groupValues?.get(1)
}

private fun displayName(label: String?): String? {
    if (label == null) return null
    return label.substringBeforeLast(" (").ifBlank { label }
}

/**
 * Launch the owning app, or open its App-info screen when it has no launcher, or
 * fall back to the system's app-list settings when the owner can't be resolved.
 * Guarantees one of those three — tapping "Open app" always takes the user
 * somewhere — and uses only intents available on every supported Android version.
 */
private fun openApp(ctx: Context, label: String?): String {
    val pkg = pkgOf(label) ?: uidPkg(ctx, label)
    if (pkg != null) {
        runCatching {
            val launch = ctx.packageManager.getLaunchIntentForPackage(pkg)
            if (launch != null) {
                ctx.startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); return "Opening $pkg…"
            }
        }
        val details = runCatching {
            ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:$pkg")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            true
        }.getOrDefault(false)
        if (details) return "No launcher — opened App info for $pkg."
    }
    // Owner not resolvable (e.g. shared system uid): open the app-list settings so
    // the user can still reach app details from one tap.
    return runCatching {
        ctx.startActivity(Intent(Settings.ACTION_APPLICATION_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        "Couldn't resolve the owning app — opened Apps settings."
    }.getOrDefault("No app could be opened for this flow.")
}

private fun uidPkg(ctx: Context, label: String?): String? {
    val uid = Regex("uid (\\d+)").find(label ?: "")?.groupValues?.get(1)?.toIntOrNull() ?: return null
    return runCatching {
        ctx.packageManager.getPackagesForUid(uid)?.firstOrNull()
            ?: ctx.packageManager.getPackagesForUid(uid % 100000)?.firstOrNull()
    }.getOrNull()
}

private fun locationLine(f: ConnectionFlow): String =
    listOfNotNull(f.org, f.country?.let { CountryNames.display(it) }).joinToString("  ·  ")

/** Printable-ASCII rendering of a payload sample (non-printables shown as dots). */
private fun printable(bytes: ByteArray, len: Int): String {
    val n = len.coerceAtMost(bytes.size)
    val sb = StringBuilder(n)
    for (i in 0 until n) {
        val b = bytes[i].toInt() and 0xFF
        sb.append(if (b in 0x20..0x7E || b == 0x0A || b == 0x09) b.toChar() else '.')
    }
    return sb.toString()
}

@Composable
private fun AppIcon(label: String?, size: androidx.compose.ui.unit.Dp) {
    val ctx = LocalContext.current
    val pkg = pkgOf(label)
    val bmp: ImageBitmap? = remember(pkg) {
        if (pkg == null) null
        else runCatching {
            val d = ctx.packageManager.getApplicationIcon(pkg)
            val w = d.intrinsicWidth.takeIf { it > 0 } ?: 96
            val h = d.intrinsicHeight.takeIf { it > 0 } ?: 96
            val b = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            val c = Canvas(b); d.setBounds(0, 0, w, h); d.draw(c)
            b.asImageBitmap()
        }.getOrNull()
    }
    if (bmp != null) {
        Image(bmp, contentDescription = displayName(label), contentScale = ContentScale.Fit,
            modifier = Modifier.size(size).clip(RoundedCornerShape(8.dp)))
    } else {
        Box(Modifier.size(size).clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant), contentAlignment = Alignment.Center) {
            Icon(Icons.Filled.Android, contentDescription = "app",
                tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(size * 0.6f))
        }
    }
}

private fun human(bytes: Long): String = when {
    bytes >= 1_000_000_000 -> "%.1fG".format(bytes / 1e9)
    bytes >= 1_000_000 -> "%.1fM".format(bytes / 1e6)
    bytes >= 1_000 -> "%.1fK".format(bytes / 1e3)
    else -> "$bytes B"
}

private fun exportCapture(ctx: Context): String {
    val path = CaptureController.lastPcapPath ?: return "No capture file yet."
    val src = File(path)
    if (!src.exists()) return "Capture file not found."
    return saveToDownloads(ctx, src.name, "application/octet-stream") { out -> src.inputStream().use { it.copyTo(out) } }
}

private fun exportHar(ctx: Context, flows: List<ConnectionFlow>): String {
    val har = HarExport.build(flows) ?: return "No cleartext HTTP observed to export."
    val name = "packetra-capture-${System.currentTimeMillis()}.har"
    return saveToDownloads(ctx, name, "application/json") { out -> out.write(har.toByteArray()) }
}

private fun saveToDownloads(ctx: Context, name: String, mime: String, write: (java.io.OutputStream) -> Unit): String {
    return try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, mime)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = ctx.contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return "Could not create Downloads entry."
            resolver.openOutputStream(uri)?.use { write(it) } ?: return "Could not open output."
            values.clear(); values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
            "Saved $name to Downloads."
        } else {
            val dir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
            val f = File(dir, name); f.outputStream().use { write(it) }
            "Saved to ${f.absolutePath}"
        }
    } catch (t: Throwable) { "Export failed: ${t.message}" }
}

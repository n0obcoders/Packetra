package com.reconx.sentinel.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.feature.netdiscovery.NmapCommand
import com.reconx.sentinel.feature.netdiscovery.PortSpec
import com.reconx.sentinel.feature.netdiscovery.ScanConfig
import com.reconx.sentinel.feature.netdiscovery.ScanEvent
import com.reconx.sentinel.feature.netdiscovery.ScanType
import com.reconx.sentinel.feature.netdiscovery.TcpConnectScanner
import com.reconx.sentinel.feature.netdiscovery.Timing
import com.reconx.sentinel.ui.SentinelViewModel
import kotlinx.coroutines.Job

private enum class ScanTab(val label: String) { GUIDED("Guided"), COMMAND("Command") }

@Composable
fun ScannerScreen(vm: SentinelViewModel) {
    val e by vm.engagement.collectAsState()
    // State lives in the ViewModel cache, so a scan's results and inputs survive
    // navigating away and back, and the scan keeps running in the background.
    var tab by vmState(vm, "scan.tab", ScanTab.GUIDED)

    var statusLine by vmState(vm, "scan.status", "")
    var progress by vmState(vm, "scan.progress", 0f)
    val openPorts = vmList<String>(vm, "scan.openPorts")
    var summary by vmState(vm, "scan.summary", "")
    var running by vmState(vm, "scan.running", false)
    var job by vmState<Job?>(vm, "scan.job", null)

    var host by vmState(vm, "scan.host", "")
    var portSpecText by vmState(vm, "scan.ports", "common")
    var timing by vmState(vm, "scan.timing", Timing.T3)
    var scanType by vmState(vm, "scan.type", ScanType.TCP_CONNECT)
    var serviceDetect by vmState(vm, "scan.sv", true)
    var noPing by vmState(vm, "scan.pn", false)
    var command by vmState(vm, "scan.cmd", "nmap -sV -T4 -p 1-1000 ")
    var cmdError by vmState(vm, "scan.cmdErr", "")

    fun runScan(h: String, cfg: ScanConfig, label: String) {
        openPorts.clear(); summary = ""; progress = 0f; running = true; statusLine = "Starting…"
        val scanner = TcpConnectScanner(vm.scopeValidator(), vm.dispatchers)
        job = vm.vmLaunch {
            scanner.scan(h.trim(), cfg).collect { ev ->
                when (ev) {
                    is ScanEvent.Resolved ->
                        statusLine = "${ev.host} → ${ev.ip} · ${ev.totalPorts} ports ($label, ${cfg.timing.label}, ${cfg.scanType})"
                    is ScanEvent.Host -> statusLine = "Host is ${if (ev.up) "UP" else "DOWN/filtered"} (${ev.method})"
                    is ScanEvent.Open -> {
                        val r = ev.result
                        val state = if (cfg.scanType == ScanType.UDP) "OPEN/udp" else "OPEN"
                        openPorts.add("$state  ${r.port}  ${r.serviceGuess ?: "?"}  ${r.product ?: ""}")
                    }
                    is ScanEvent.Progress -> { progress = ev.scanned.toFloat() / ev.total
                        statusLine = "Scanned ${ev.scanned}/${ev.total} · ${ev.open} open" }
                    is ScanEvent.Done -> {
                        summary = if (ev.scanned == 0) statusLine
                            else "Done: ${ev.open} open, ${ev.closed} closed, ${ev.filtered} filtered/open " +
                                "of ${ev.scanned} in ${ev.elapsedMs} ms"
                        running = false
                    }
                    is ScanEvent.Failed -> { statusLine = ev.reason; running = false }
                }
            }
            running = false
        }
    }

    ScreenColumn {
        ScopeBanner(e)
        TabRow(selectedTabIndex = tab.ordinal) {
            ScanTab.entries.forEach { Tab(selected = tab == it, onClick = { tab = it }, text = { Text(it.label) }) }
        }

        when (tab) {
            ScanTab.GUIDED -> SectionCard("Guided scan") {
                OutlinedTextField(host, { host = it }, label = { Text("Authorized host or IP") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ScanType.entries.forEach { st ->
                        FilterChip(selected = scanType == st, onClick = { scanType = st },
                            label = { Text(when (st) { ScanType.TCP_CONNECT -> "TCP"; ScanType.UDP -> "UDP"; ScanType.PING_SWEEP -> "Ping" }) })
                    }
                }
                if (scanType != ScanType.PING_SWEEP)
                    OutlinedTextField(portSpecText, { portSpecText = it },
                        label = { Text("Ports (1-1024, 80,443, top100, -, web)") },
                        singleLine = true, modifier = Modifier.fillMaxWidth())
                Text("Timing", style = MaterialTheme.typography.labelLarge)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Timing.entries.forEach { t -> FilterChip(selected = timing == t, onClick = { timing = t }, label = { Text(t.label) }) }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(serviceDetect, { serviceDetect = it }); Spacer(Modifier.width(8.dp)); Text("Service/version (-sV)") }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(noPing, { noPing = it }); Spacer(Modifier.width(8.dp)); Text("Skip host discovery (-Pn)") }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = !running && host.isNotBlank(), onClick = {
                        val (ports, label) = PortSpec.parse(portSpecText)
                        runScan(host, ScanConfig(timing, ports, serviceDetect, label, scanType, !noPing), label)
                    }) { Text(if (running) "Scanning…" else "Start scan") }
                    if (running) OutlinedButton(onClick = { job?.cancel(); running = false; summary = "Cancelled." }) { Text("Stop") }
                }
            }
            ScanTab.COMMAND -> SectionCard("Command editor (nmap-style subset)") {
                Text("Parsed into the on-device scanner — never run as a shell. " +
                    NMAP_HELP, style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(command, { command = it; cmdError = "" },
                    label = { Text("command") }, modifier = Modifier.fillMaxWidth())
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = !running, onClick = {
                        val r = NmapCommand.parse(command)
                        if (r.errors.isNotEmpty()) { cmdError = r.errors.joinToString("\n"); return@Button }
                        val cfg = r.config!!
                        runScan(r.target ?: "", cfg, cfg.portLabel)
                    }) { Text(if (running) "Scanning…" else "Run") }
                    if (running) OutlinedButton(onClick = { job?.cancel(); running = false; summary = "Cancelled." }) { Text("Stop") }
                }
                if (cmdError.isNotBlank()) Text(cmdError, color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall)
            }
        }

        if (running) LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
        if (statusLine.isNotBlank()) Text(statusLine, style = MaterialTheme.typography.bodySmall)
        if (openPorts.isNotEmpty()) SectionCard("Open ports (${openPorts.size})") { openPorts.forEach { Mono(it) } }
        if (summary.isNotBlank()) SectionCard("Summary") { Mono(summary) }

        SectionCard("About") {
            Text("Connect and UDP scans complete normal handshakes/queries — an open port is not a " +
                "vulnerability by itself. SYN/stealth scanning needs root and is not offered. UDP ports " +
                "with no reply are reported as open|filtered (honest, since reading ICMP needs root). " +
                "Targets outside your list are refused.", style = MaterialTheme.typography.bodySmall)
        }
    }
}

private const val NMAP_HELP = "Supported: -sT -sU -sn -Pn -p <ports> -F --top-ports N -T0..5 -sV -n <target>"

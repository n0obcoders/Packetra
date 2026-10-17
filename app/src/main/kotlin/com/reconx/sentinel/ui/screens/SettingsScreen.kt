package com.reconx.sentinel.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.core.security.EngagementStatus
import com.reconx.sentinel.ui.SentinelViewModel

@Composable
fun SettingsScreen(vm: SentinelViewModel) {
    val e by vm.engagement.collectAsState()
    var domains by remember { mutableStateOf(e.domains.joinToString("\n")) }
    var cidrs by remember { mutableStateOf(e.cidrs.joinToString("\n")) }
    var exclusions by remember { mutableStateOf(e.exclusions.joinToString("\n")) }
    var saved by remember { mutableStateOf(false) }

    ScreenColumn {
        SectionCard("Targets") {
            Text("Hosts, domains and IP ranges you are authorized to assess. Active modules " +
                "(scanner, discovery, web checks) only run against what you list here; anything " +
                "else is refused. Cloud metadata endpoints are always blocked.",
                style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(domains, { domains = it; saved = false },
                label = { Text("Hosts / domains (one per line)") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(cidrs, { cidrs = it; saved = false },
                label = { Text("IP ranges / CIDRs (one per line)") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(exclusions, { exclusions = it; saved = false },
                label = { Text("Exclusions (optional)") }, modifier = Modifier.fillMaxWidth())
            Button(onClick = {
                vm.updateEngagement {
                    it.copy(
                        name = "on-device",
                        domains = domains.lines().map(String::trim).filter(String::isNotEmpty),
                        cidrs = cidrs.lines().map(String::trim).filter(String::isNotEmpty),
                        exclusions = exclusions.lines().map(String::trim).filter(String::isNotEmpty),
                        labConfirmed = true,
                        status = EngagementStatus.APPROVED,
                    )
                }
                saved = true
            }) { Text("Save targets") }
            if (saved) Text("Saved — ${domains.lines().count { it.isNotBlank() }} host(s), " +
                "${cidrs.lines().count { it.isNotBlank() }} range(s) active.",
                style = MaterialTheme.typography.bodySmall)
        }
        SectionCard("Localhost dashboard") {
            Text("Served from the Localhost Dashboard screen on 127.0.0.1. Loopback-only by " +
                "default; LAN exposure is a separate explicit toggle there.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

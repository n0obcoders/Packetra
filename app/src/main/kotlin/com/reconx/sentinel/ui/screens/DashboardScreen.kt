package com.reconx.sentinel.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.reconx.sentinel.BuildConfig
import com.reconx.sentinel.ui.SentinelViewModel
import com.reconx.sentinel.ui.nav.Dest

@Composable
fun DashboardScreen(vm: SentinelViewModel, nav: NavController) {
    val e by vm.engagement.collectAsState()
    ScreenColumn {
        ScopeBanner(e)
        SectionCard("Workstation status") {
            Text("Capture: idle · Active assessments: 0")
            Text("Scope: ${if (e.hasScope) "${e.domains.size} domains, ${e.cidrs.size} ranges" else "none"}")
            Text("Build ${BuildConfig.VERSION_NAME} (code ${BuildConfig.VERSION_CODE})",
                style = MaterialTheme.typography.bodySmall)
        }
        SectionCard("Quick actions") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = { nav.navigate(Dest.SETTINGS.route) }) { Text("Set scope") }
                FilledTonalButton(onClick = { nav.navigate(Dest.SCANNER.route) }) { Text("Scan") }
                FilledTonalButton(onClick = { nav.navigate(Dest.SUBDOMAINS.route) }) { Text("Subdomains") }
            }
        }
        SectionCard("Capabilities") {
            Text("• Subdomain discovery (passive OSINT, CT logs, DNS) — on-device", style = MaterialTheme.typography.bodySmall)
            Text("• TCP connect scanning (non-root) — on-device, scope-gated", style = MaterialTheme.typography.bodySmall)
            Text("• Web security-header / cookie / TLS review — on-device", style = MaterialTheme.typography.bodySmall)
            Text("• Local VPN traffic capture (device's own traffic) — non-root", style = MaterialTheme.typography.bodySmall)
            Text("• ReconX platform launcher — drives your ReconX instance", style = MaterialTheme.typography.bodySmall)
        }
    }
}

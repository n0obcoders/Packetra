package com.reconx.sentinel.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/** "About me" — the author, their GitHub, the project repo, and a portfolio link. */
@Composable
fun AboutScreen() {
    val ctx = LocalContext.current
    fun open(url: String) = runCatching {
        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    ScreenColumn {
        SectionCard("About me") {
            Text("Nitin Shukla", style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold)
            Text("Builder of Packetra — an authorized, defensive-first Android network " +
                "visibility and security-assessment toolkit. I like networks, reconnaissance " +
                "and making the invisible parts of a connection readable.",
                style = MaterialTheme.typography.bodyMedium)
        }

        SectionCard("Links") {
            LinkRow(Icons.Filled.Code, "GitHub", "github.com/n0obcoders") { open("https://github.com/n0obcoders") }
            LinkRow(Icons.Filled.Code, "Project repo", "github.com/n0obcoders/packetra") { open("https://github.com/n0obcoders/packetra") }
            LinkRow(Icons.Filled.Language, "Portfolio", "n0obcoders.github.io/portfoli0") { open("https://n0obcoders.github.io/portfoli0") }
        }

        SectionCard("n3-editor — pcap reader / advanced notepad") {
            Text("n3-editor is an advanced notepad and PCAP reader. Export a capture from the " +
                "Packet Analyzer and open it in n3-editor to read every packet and what it carries.",
                style = MaterialTheme.typography.bodySmall)
            LinkRow(Icons.Filled.Code, "n3-editor", "github.com/n3-editor") { open("https://github.com/n3-editor") }
        }

        SectionCard("About Packetra") {
            Text("Packetra captures your own device's traffic (non-root VpnService), maps flows to " +
                "apps, geo and ASN, classifies protocols, and exports PCAPng/HAR for Wireshark — " +
                "alongside passive recon, a scope-gated scanner, and web-assessment modules. " +
                "It never decrypts TLS and is built for authorized use only.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun LinkRow(icon: ImageVector, label: String, value: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary)
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(value, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
        }
        Icon(Icons.Filled.OpenInNew, "open", modifier = Modifier.size(18.dp))
    }
}

package com.reconx.sentinel.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * One-time first-launch greeting. Shown until the user taps "Get started"; the
 * caller persists the "seen" flag so it never appears again.
 */
@Composable
fun WelcomeScreen(onGetStarted: () -> Unit) {
    val ctx = LocalContext.current
    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(18.dp),
        ) {
            Spacer(Modifier.height(24.dp))
            Text("Welcome to Packetra", style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold, textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.primary)
            Text("made by Nitin Shukla", style = MaterialTheme.typography.titleMedium,
                textAlign = TextAlign.Center)

            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("What is Packetra?", style = MaterialTheme.typography.titleMedium)
                    Text("Packetra is an authorized, defensive-first network-visibility and " +
                        "security-assessment toolkit for Android. It captures your own device's " +
                        "traffic without root, maps every flow to its app, geo and network, " +
                        "classifies protocols, and exports PCAPng/HAR for Wireshark — plus passive " +
                        "recon, a scope-gated scanner and web-assessment checks.",
                        style = MaterialTheme.typography.bodyMedium)
                    Text("It never decrypts TLS and is built strictly for systems you own or are " +
                        "authorized to assess.", style = MaterialTheme.typography.bodySmall)
                }
            }

            OutlinedButton(onClick = {
                runCatching {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW,
                        Uri.parse("https://github.com/n0obcoders/packetra"))
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }
            }, modifier = Modifier.fillMaxWidth()) {
                Text("View on GitHub — n0obcoders/packetra")
            }

            Button(onClick = onGetStarted, modifier = Modifier.fillMaxWidth()) {
                Text("Get started")
            }
            Spacer(Modifier.height(12.dp))
        }
    }
}

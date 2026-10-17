package com.reconx.sentinel.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.feature.authaudit.BruteForceSimulation
import com.reconx.sentinel.feature.authaudit.PasswordPolicy
import com.reconx.sentinel.feature.authaudit.PasswordPolicyAuditor
import com.reconx.sentinel.ui.SentinelViewModel

private enum class AuthTab(val label: String) { POLICY("Policy review"), SIM("Attack simulation"), REF("Engine reference") }

@Composable
fun AuthAuditScreen(vm: SentinelViewModel) {
    // Inputs and results persist across navigation via the ViewModel cache.
    var tab by vmState(vm, "auth.tab", AuthTab.POLICY)
    ScreenColumn {
        SectionCard("Authentication audit") {
            Text("Defensive configuration review and a no-traffic attack simulation. This module " +
                "performs no live credential testing against any service.",
                style = MaterialTheme.typography.bodySmall)
            TabRow(selectedTabIndex = tab.ordinal) {
                AuthTab.entries.forEach { Tab(selected = tab == it, onClick = { tab = it }, text = { Text(it.label) }) }
            }
        }
        when (tab) {
            AuthTab.POLICY -> PolicyTab(vm)
            AuthTab.SIM -> SimTab(vm)
            AuthTab.REF -> RefTab()
        }
    }
}

@Composable
private fun ColumnScope.PolicyTab(vm: SentinelViewModel) {
    var minLen by vmState(vm, "auth.minLen", "8")
    var mfa by vmState(vm, "auth.mfa", false)
    var rate by vmState(vm, "auth.rate", true)
    var breached by vmState(vm, "auth.breached", false)
    val findings = vmList<String>(vm, "auth.findings")
    SectionCard("Declared policy") {
        OutlinedTextField(minLen, { minLen = it.filter(Char::isDigit).take(3) },
            label = { Text("Minimum password length") }, singleLine = true)
        Row(verticalAlignment = Alignment.CenterVertically) { Switch(mfa, { mfa = it }); Text("  MFA required") }
        Row(verticalAlignment = Alignment.CenterVertically) { Switch(rate, { rate = it }); Text("  Rate limiting / lockout") }
        Row(verticalAlignment = Alignment.CenterVertically) { Switch(breached, { breached = it }); Text("  Blocks breached passwords") }
        Button(onClick = {
            findings.clear()
            val p = PasswordPolicy(minLen.toIntOrNull() ?: 0, mfa, if (rate) 5 else null, rate, null, breached)
            PasswordPolicyAuditor.audit("declared-policy", p).forEach { findings.add("[${it.severity}] ${it.title}") }
            if (findings.isEmpty()) findings.add("No policy weaknesses identified.")
        }) { Text("Evaluate policy") }
    }
    if (findings.isNotEmpty()) SectionCard("Policy findings") { findings.forEach { Mono(it) } }
}

@Composable
private fun ColumnScope.SimTab(vm: SentinelViewModel) {
    var list by vmState(vm, "auth.sim.list", "10000")
    var rate by vmState(vm, "auth.sim.rate", "60")
    var lockout by vmState(vm, "auth.sim.lockout", "5")
    var srvRate by vmState(vm, "auth.sim.srvRate", "10")
    var mfa by vmState(vm, "auth.sim.mfa", false)
    var hitIndex by vmState(vm, "auth.sim.hit", "4200")
    val out = vmList<String>(vm, "auth.sim.out")

    SectionCard("Brute-force simulation (no network traffic)") {
        Text("Models how an online guessing attack would fare against these defenses — purely a " +
            "calculation, nothing is sent anywhere.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(list, { list = it.filter(Char::isDigit).take(9) }, label = { Text("Attacker list size") }, singleLine = true)
        OutlinedTextField(rate, { rate = it.filter(Char::isDigit).take(6) }, label = { Text("Attacker guesses/min") }, singleLine = true)
        OutlinedTextField(lockout, { lockout = it.filter(Char::isDigit).take(4) }, label = { Text("Lockout threshold (blank=none)") }, singleLine = true)
        OutlinedTextField(srvRate, { srvRate = it.filter(Char::isDigit).take(5) }, label = { Text("Server rate-limit/min (blank=none)") }, singleLine = true)
        OutlinedTextField(hitIndex, { hitIndex = it.filter(Char::isDigit).take(9) }, label = { Text("Correct password position (blank=not in list)") }, singleLine = true)
        Row(verticalAlignment = Alignment.CenterVertically) { Switch(mfa, { mfa = it }); Text("  MFA enabled") }
        Button(onClick = {
            out.clear()
            val s = BruteForceSimulation.Scenario(
                candidatePasswords = list.toIntOrNull() ?: 0,
                guessesPerMinute = rate.toIntOrNull() ?: 1,
                lockoutThreshold = lockout.toIntOrNull(),
                lockoutMinutes = 15,
                rateLimitPerMinute = srvRate.toIntOrNull(),
                mfaEnabled = mfa,
                correctGuessIndex = hitIndex.toIntOrNull(),
            )
            val r = BruteForceSimulation.run(s)
            r.narrative.forEach { out.add(it) }
            out.add("—")
            r.defensiveFindings.forEach { out.add("• $it") }
        }) { Text("Run simulation") }
    }
    if (out.isNotEmpty()) SectionCard("Simulation result") { out.forEach { Mono(it) } }
}

@Composable
private fun ColumnScope.RefTab() {
    SectionCard("Authentication-attack engines (reference)") {
        Text("THC Hydra and Medusa are the standard online login auditing tools. They support " +
            "protocols such as HTTP(S) form/basic, FTP, SSH, SMB, RDP, SMTP, POP3, IMAP, MySQL, " +
            "PostgreSQL and more. On desktop/Kali they run as native binaries.",
            style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(8.dp))
        Text("Why this app simulates rather than runs them live:", style = MaterialTheme.typography.titleSmall)
        Text("A live online brute-forcer that can be pointed at any host entered in a box is an " +
            "offensive weapon regardless of intent, and the ReconX spec rules out password brute " +
            "force. The simulation above lets you reason about and demonstrate the same defensive " +
            "concepts — lockout, rate limiting, MFA, list size — safely.",
            style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(8.dp))
        Text("Defensive takeaways:", style = MaterialTheme.typography.titleSmall)
        Text("• MFA defeats online password guessing outright.\n" +
            "• Lockout + server rate limiting bound how far any attacker gets.\n" +
            "• Breached-password screening removes the easy wins.\n" +
            "• Length/entropy makes exhaustive lists impractical.",
            style = MaterialTheme.typography.bodySmall)
    }
}

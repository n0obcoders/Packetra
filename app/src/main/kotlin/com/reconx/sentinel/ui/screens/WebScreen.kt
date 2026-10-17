package com.reconx.sentinel.ui.screens

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.provider.MediaStore
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Outcome
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification
import com.reconx.sentinel.core.network.HttpClients
import com.reconx.sentinel.feature.recon.DohResolver
import com.reconx.sentinel.feature.recon.EmailSecurity
import com.reconx.sentinel.feature.recon.RdapClient
import com.reconx.sentinel.feature.recon.SubdomainEngine
import com.reconx.sentinel.feature.recon.SubdomainTakeover
import com.reconx.sentinel.feature.web.CspAnalyzer
import com.reconx.sentinel.feature.web.Cvss
import com.reconx.sentinel.feature.web.RiskPrioritizer
import com.reconx.sentinel.feature.web.FixSnippets
import com.reconx.sentinel.feature.web.NiktoChecks
import com.reconx.sentinel.feature.web.WebAssessor
import com.reconx.sentinel.feature.web.WebReport
import com.reconx.sentinel.feature.web.WebScanner
import com.reconx.sentinel.ui.SentinelViewModel
import kotlinx.coroutines.withContext

@Composable
fun WebScreen(vm: SentinelViewModel) {
    val e by vm.engagement.collectAsState()
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    // State persists across navigation via the ViewModel cache; work runs on the
    // ViewModel scope so it keeps going when the user switches screens.
    var url by vmState(vm, "web.url", "https://")
    var status by vmState(vm, "web.status", "")
    var report by vmState<WebReport?>(vm, "web.report", null)
    val nikto = vmList<String>(vm, "web.nikto")
    var niktoStatus by vmState(vm, "web.niktoStatus", "")

    // Deep-scan state
    var deepStatus by vmState(vm, "web.deepStatus", "")
    val techs = vmList<String>(vm, "web.techs")
    val deepFindings = vmList<FindingLine>(vm, "web.deepFindings")
    val triage = vmList<TriageLine>(vm, "web.triage")
    var deepJson by vmState(vm, "web.deepJson", "")
    var deepSarif by vmState(vm, "web.deepSarif", "")
    var deepMarkdown by vmState(vm, "web.deepMarkdown", "")

    // Recon state (DNS, WHOIS/RDAP, passive subdomains, CSP cross-reference)
    var reconStatus by vmState(vm, "web.reconStatus", "")
    val dnsLines = vmList<String>(vm, "web.dns")
    var whoisText by vmState(vm, "web.whois", "")
    val reconSubs = vmList<String>(vm, "web.reconSubs")
    var cspNote by vmState(vm, "web.cspNote", "")
    val takeoverLinesState = vmList<String>(vm, "web.takeover")
    var driftText by vmState(vm, "web.drift", "")

    ScreenColumn {
        ScopeBanner(e)
        SectionCard("Web security assessment (non-destructive)") {
            OutlinedTextField(url, { url = it }, label = { Text("Authorized URL") },
                singleLine = true, modifier = Modifier.fillMaxWidth())

            Button(enabled = url.length > 8, onClick = {
                deepStatus = "Running all checks…"; techs.clear(); deepFindings.clear(); triage.clear()
                deepJson = ""; deepSarif = ""; deepMarkdown = ""
                val u = url.trim()
                vm.vmLaunch {
                    try {
                        val sv = vm.scopeValidator()
                        val all = mutableListOf<Finding>()
                        when (val r = WebAssessor(sv, vm.dispatchers).assess(u)) {
                            is Outcome.Ok -> { report = r.value; status = ""; all += r.value.findings }
                            is Outcome.Err -> { deepStatus = r.message; return@vmLaunch }
                        }
                        runCatching { NiktoChecks(sv, vm.dispatchers).run(u) }.getOrNull()
                            ?.let { (it as? Outcome.Ok)?.value?.let { f -> all += f } }
                        when (val s = runCatching { WebScanner(sv, vm.dispatchers).scan(u) }
                            .getOrElse { Outcome.Err("deep scan error: ${it.message}") }) {
                            is Outcome.Ok -> {
                                all += s.value.findings
                                s.value.techs.forEach { techs.add(it.name + (it.version?.let { v -> " $v" } ?: "")) }
                            }
                            is Outcome.Err -> deepStatus = s.message
                        }
                        // Email-spoofing posture (passive DNS: SPF/DMARC/DKIM/DNSSEC).
                        // Runs on IO and is fully guarded so a DNS failure never aborts the scan.
                        emailHost(u)?.let { host ->
                            runCatching {
                                withContext(vm.dispatchers.io) { EmailSecurity(DohResolver()).assess(host) }
                            }.getOrNull()?.let { (it as? Outcome.Ok)?.value }?.let { checks ->
                                all += checks.mapNotNull { emailFinding(host, it) }
                            }
                        }
                        val merged = all.distinctBy { it.title + it.target }
                            .map { it to Cvss.forFinding(it) }
                            .sortedWith(compareByDescending<Pair<Finding, Cvss.Score>> { it.first.severity.rank }
                                .thenByDescending { it.second.base })
                        merged.forEach { (f, c) -> deepFindings.add(FindingLine(f, c.base, c.label, c.vector)) }
                        RiskPrioritizer.prioritize(all).forEach { g ->
                            triage.add(TriageLine(RiskPrioritizer.label(g.priority), g.representative.title,
                                g.representative.category, g.count, g.targets.size, g.score))
                        }
                        deepJson = buildJson(u, merged)
                        deepSarif = buildSarif(u, merged)
                        deepMarkdown = buildMarkdown(u, merged)
                        deepStatus = if (merged.isEmpty()) "No issues flagged." else "${merged.size} finding(s)"
                    } catch (t: Throwable) {
                        deepStatus = "Scan error: ${t.message ?: t.javaClass.simpleName}. Partial results shown."
                    }
                }
            }) { Text("Deep scan (all checks)") }
            if (deepStatus.isNotBlank()) Text(deepStatus, style = MaterialTheme.typography.bodySmall)

            Button(enabled = url.length > 8, onClick = {
                reconStatus = "Running passive recon…"; dnsLines.clear(); whoisText = ""
                reconSubs.clear(); cspNote = ""; takeoverLinesState.clear(); driftText = ""
                val host = emailHost(url.trim())
                if (host == null) { reconStatus = "Could not read a host from the URL." } else {
                    val u = url.trim()
                    vm.vmLaunch {
                        try {
                            val dns = mutableListOf<String>()
                            var whois = ""
                            val subs = mutableListOf<String>()
                            var note = ""
                            val takeovers = mutableListOf<String>()
                            var drift = ""
                            withContext(vm.dispatchers.io) {
                                val doh = DohResolver()
                                for (t in listOf("A", "AAAA", "MX", "TXT", "CNAME", "NS")) {
                                    (doh.query(host, t) as? Outcome.Ok)?.value?.Answer.orEmpty().forEach { a ->
                                        a.data?.let { dns += "$t   ${it.trim('"').take(120)}" }
                                    }
                                }
                                (RdapClient().lookup(host) as? Outcome.Ok)?.value?.let { w ->
                                    whois = buildString {
                                        w.registrar?.let { append("Registrar : $it\n") }
                                        w.registered?.let { append("Registered: $it\n") }
                                        w.expires?.let { append("Expires   : $it\n") }
                                        w.lastChanged?.let { append("Updated   : $it\n") }
                                        if (w.nameservers.isNotEmpty()) append("NS        : ${w.nameservers.joinToString(", ")}\n")
                                        if (w.statuses.isNotEmpty()) append("Status    : ${w.statuses.joinToString(", ")}")
                                    }.trim()
                                }
                                val subHosts = mutableListOf<String>()
                                (SubdomainEngine(vm.dispatchers).discover(host, validate = false)).subs.forEach { s ->
                                    subs += "${s.host}   [${s.sources.joinToString("+")}]"
                                    subHosts += s.host
                                }
                                // CSP subdomain-trust cross-reference: fetch the live CSP and match discovered subs.
                                runCatching {
                                    HttpClients.assessment(false).newCall(
                                        okhttp3.Request.Builder().url(u)
                                            .header("User-Agent", HttpClients.USER_AGENT).get().build()
                                    ).execute().use { it.header("Content-Security-Policy") }
                                }.getOrNull()?.let { csp ->
                                    val bases = CspAnalyzer.wildcardSubdomainBases(csp)
                                    if (bases.isNotEmpty()) {
                                        val matched = subHosts.filter { h -> bases.any { b -> h == b || h.endsWith(".$b") } }
                                        note = "CSP trusts " + bases.joinToString(", ") { "*.$it" } + ". " +
                                            if (matched.isNotEmpty())
                                                "${matched.size} discovered subdomain(s) fall under it — taking over any one " +
                                                    "(e.g. ${matched.take(3).joinToString(", ")}) becomes a CSP bypass on the main site."
                                            else "Any forgotten subdomain under it that an attacker takes over becomes a CSP-trusted script source."
                                    }
                                }
                                // Subdomain-takeover detection on discovered hosts (passive CNAME + fingerprint).
                                runCatching { SubdomainTakeover(vm.dispatchers).check(subHosts) }.getOrNull()?.forEach { f ->
                                    takeovers += "[${f.severity}] ${f.title}"
                                }
                                // Drift vs. the last saved baseline for this host.
                                runCatching {
                                    val prev = loadBaseline(ctx, host)
                                    val cur = subHosts.map { it.lowercase() }.toSortedSet()
                                    drift = if (prev == null) "First scan for $host — baseline of ${cur.size} subdomain(s) saved."
                                    else {
                                        val added = (cur - prev).toList()
                                        val removed = (prev - cur).toList()
                                        saveBaseline(ctx, host, cur)
                                        when {
                                            added.isEmpty() && removed.isEmpty() -> "No change since last scan (${cur.size} subdomains)."
                                            else -> buildString {
                                                if (added.isNotEmpty()) append("New since last scan (${added.size}): ${added.take(10).joinToString(", ")}${if (added.size > 10) "…" else ""}. ")
                                                if (removed.isNotEmpty()) append("Gone since last scan (${removed.size}): ${removed.take(10).joinToString(", ")}${if (removed.size > 10) "…" else ""}.")
                                            }
                                        }
                                    }
                                    if (prev == null) saveBaseline(ctx, host, cur)
                                }
                            }
                            dnsLines.addAll(dns); whoisText = whois; reconSubs.addAll(subs); cspNote = note
                            takeoverLinesState.addAll(takeovers); driftText = drift
                            reconStatus = "${subs.size} subdomain(s) · DNS/WHOIS gathered"
                        } catch (t: Throwable) {
                            reconStatus = "Recon error: ${t.message ?: t.javaClass.simpleName}. Partial results shown."
                        }
                    }
                }
            }) { Text("Recon (DNS, WHOIS, subdomains)") }
            if (reconStatus.isNotBlank()) Text(reconStatus, style = MaterialTheme.typography.bodySmall)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = url.length > 8, onClick = {
                    report = null; status = "Assessing…"
                    val assessor = WebAssessor(vm.scopeValidator(), vm.dispatchers)
                    vm.vmLaunch {
                        when (val r = assessor.assess(url.trim())) {
                            is Outcome.Ok -> { report = r.value; status = "" }
                            is Outcome.Err -> status = r.message
                        }
                    }
                }) { Text("Headers/TLS only") }
                OutlinedButton(enabled = url.length > 8, onClick = {
                    nikto.clear(); niktoStatus = "Running Nikto-style checks…"
                    vm.vmLaunch {
                        when (val r = NiktoChecks(vm.scopeValidator(), vm.dispatchers).run(url.trim())) {
                            is Outcome.Ok -> {
                                r.value.forEach { nikto.add("[${it.severity}] ${it.title}") }
                                niktoStatus = if (r.value.isEmpty()) "No exposed paths/methods flagged." else "${r.value.size} observation(s)"
                            }
                            is Outcome.Err -> niktoStatus = r.message
                        }
                    }
                }) { Text("Path checks") }
            }
            if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
            if (niktoStatus.isNotBlank()) Text(niktoStatus, style = MaterialTheme.typography.bodySmall)
        }

        if (techs.isNotEmpty()) SectionCard("Technology stack (${techs.size})") {
            Text("Fingerprinted passively from headers, cookies, page markers and script versions.",
                style = MaterialTheme.typography.bodySmall)
            techs.distinct().forEach { Mono("• $it") }
        }

        if (cspNote.isNotBlank()) SectionCard("CSP ↔ subdomain exposure") {
            Text(cspNote, style = MaterialTheme.typography.bodySmall)
        }

        if (whoisText.isNotBlank()) SectionCard("Registrar / WHOIS (RDAP)") { Mono(whoisText) }

        if (dnsLines.isNotEmpty()) SectionCard("DNS records (${dnsLines.size})") {
            Text("Resolved via DNS-over-HTTPS (passive from the target's view).",
                style = MaterialTheme.typography.bodySmall)
            dnsLines.forEach { Mono(it) }
        }

        if (takeoverLinesState.isNotEmpty()) SectionCard("Subdomain takeover (${takeoverLinesState.size})") {
            Text("CNAMEs that delegate to third-party services, checked for dangling/unclaimed pointers. " +
                "A HIGH item means the service is serving its 'unclaimed' page — re-point or remove the record.",
                style = MaterialTheme.typography.bodySmall)
            takeoverLinesState.forEach { Mono(it) }
        }

        if (driftText.isNotBlank()) SectionCard("Drift since last scan") {
            Text(driftText, style = MaterialTheme.typography.bodySmall)
        }

        if (reconSubs.isNotEmpty()) SectionCard("Subdomains (${reconSubs.size})") {
            Text("Passive enumeration from CT logs and public datasets — no direct probing of the target.",
                style = MaterialTheme.typography.bodySmall)
            reconSubs.take(200).forEach { Mono("• $it") }
            if (reconSubs.size > 200) Mono("…and ${reconSubs.size - 200} more")
        }

        if (triage.isNotEmpty()) SectionCard("Risk-based triage (${triage.size} groups)") {
            Text("Grouped and deduplicated, ordered by contextual risk (severity weighted by how confirmed each " +
                "finding is), not raw CVSS alone — so verified issues rank above theoretical ones.",
                style = MaterialTheme.typography.bodySmall)
            triage.forEach { t ->
                Spacer(Modifier.height(4.dp))
                Text("${t.priorityLabel} · ${t.title}", style = MaterialTheme.typography.titleSmall)
                Mono("score ${"%.1f".format(t.score)} · ${t.category}" +
                    (if (t.count > 1) " · ${t.count} occurrences across ${t.targetCount} target(s)" else ""))
            }
        }

        if (deepFindings.isNotEmpty()) {
            SectionCard("Findings — ${deepFindings.size} (CVSS 3.1 indicative)") {
                Text("Sorted by severity. CVSS scores are indicative base scores for triage, not final.",
                    style = MaterialTheme.typography.bodySmall)
                deepFindings.forEach { fl ->
                    val f = fl.finding
                    Spacer(Modifier.height(6.dp))
                    Text("[${f.severity}] ${f.title}", style = MaterialTheme.typography.titleSmall)
                    Mono("CVSS ${"%.1f".format(fl.cvss)} (${fl.label}) · ${f.confidence} · ${f.category}")
                    if (f.explanation.isNotBlank()) Text(f.explanation, style = MaterialTheme.typography.bodySmall)
                    if (f.remediation.isNotBlank())
                        Text("Fix: ${f.remediation}", style = MaterialTheme.typography.bodySmall)
                    FixSnippetsBlock(f)
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { clipboard.setText(AnnotatedString(deepJson)) }) { Text("Copy JSON") }
                    OutlinedButton(onClick = {
                        deepStatus = saveFile(ctx, "packetra-web-report", "json", "application/json", deepJson)
                    }) { Text("Export JSON") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        deepStatus = saveFile(ctx, "packetra-web-report", "sarif", "application/json", deepSarif)
                    }) { Text("Export SARIF") }
                    OutlinedButton(onClick = {
                        deepStatus = saveFile(ctx, "packetra-web-report", "md", "text/markdown", deepMarkdown)
                    }) { Text("Export Markdown") }
                    OutlinedButton(onClick = { clipboard.setText(AnnotatedString(deepMarkdown)) }) { Text("Copy MD") }
                }
            }
        }

        report?.let { rep ->
            SectionCard("Response") {
                Mono("Status : ${rep.statusLine}")
                Mono("Final  : ${rep.finalUrl}")
                rep.server?.let { Mono("Server : $it") }
                rep.title?.let { Mono("Title  : $it") }
                if (rep.redirectChain.size > 1)
                    Mono("Redirects: ${rep.redirectChain.joinToString(" → ")}")
            }
            rep.tls?.let { t ->
                SectionCard("TLS") {
                    Mono("${t.version} · ${t.cipher}")
                    t.issuer?.let { Mono("Issuer : ${it.take(80)}") }
                    t.notAfter?.let { Mono("Expires: $it (${t.daysToExpiry} days)") }
                    if (t.legacyProtocols.isNotEmpty())
                        Mono("Legacy : ${t.legacyProtocols.joinToString(", ")} still negotiated")
                    if (t.sans.isNotEmpty()) {
                        Text("Subject Alternative Names (${t.sans.size}) — sibling hosts sharing this certificate:",
                            style = MaterialTheme.typography.bodySmall)
                        t.sans.take(20).forEach { Mono("• $it") }
                        if (t.sans.size > 20) Mono("…and ${t.sans.size - 20} more")
                    }
                }
            }
            if (rep.passedChecks.isNotEmpty()) PassedChecksBlock(rep.passedChecks)
            if (rep.notes.isNotEmpty()) SectionCard("Notes") {
                rep.notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }

        if (nikto.isNotEmpty()) SectionCard("Path checks (${nikto.size})") { nikto.forEach { Mono(it) } }

        SectionCard("Scope & honesty") {
            Text("All checks are scope-gated and non-destructive. Requests are GET-only (plus one standard " +
                "GraphQL introspection query); email posture, DNS, WHOIS/RDAP, certificate SANs and subdomain " +
                "enumeration are passive lookups against public datasets, not probes of the target. Secret scanning " +
                "only reads code the server already served publicly and redacts any match. " +
                "Injection, XSS and open-redirect checks send a single inert probe per parameter (a marker " +
                "token, a lone quote, a non-resolvable canary host) to RAISE a signal to confirm manually — " +
                "they are not exploits. No payloads, shells, brute-force or exfiltration. A flagged item is a " +
                "lead, not a confirmed breach.",
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun PassedChecksBlock(passed: List<com.reconx.sentinel.feature.web.PassedCheck>) {
    SectionCard("Passed / Compliant (${passed.size})") {
        var open by remember { mutableStateOf(false) }
        TextButton(onClick = { open = !open }) {
            Text(if (open) "Hide passed checks" else "Show the ${passed.size} checks that passed")
        }
        if (open) passed.forEach { c ->
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("✓", color = Color(0xFF2E7D32), style = MaterialTheme.typography.bodyMedium)
                Column {
                    Text(c.name, style = MaterialTheme.typography.bodyMedium)
                    Text(c.detail, style = MaterialTheme.typography.labelSmall)
                }
            }
            Spacer(Modifier.height(4.dp))
        }
    }
}

@Composable
private fun FixSnippetsBlock(f: Finding) {
    val snippets = remember(f.id) { FixSnippets.forFinding(f) } ?: return
    var open by remember(f.id) { mutableStateOf(false) }
    TextButton(onClick = { open = !open }) {
        Text(if (open) "Hide platform fix snippets" else "Show platform fix snippets")
    }
    if (open) snippets.forEach { (platform, block) ->
        Text(platform, style = MaterialTheme.typography.labelLarge)
        Mono(block)
        Spacer(Modifier.height(4.dp))
    }
}

// Persisted, Compose-stable holder for a rendered finding + its CVSS.
class FindingLine(val finding: Finding, val cvss: Double, val label: String, val vector: String)
class TriageLine(val priorityLabel: String, val title: String, val category: String,
                 val count: Int, val targetCount: Int, val score: Double)

// ---- email-posture mapping ----

private fun emailHost(url: String): String? = runCatching {
    java.net.URI(url.trim()).host?.removePrefix("www.")
}.getOrNull()?.takeIf { it.isNotBlank() }

private fun emailFinding(host: String, c: EmailSecurity.Check): Finding? {
    if (c.ok) return null
    val (sev, cat) = when (c.name) {
        "SPF", "DMARC" -> Severity.MEDIUM to "email_security"
        "DKIM" -> Severity.LOW to "email_security"
        "DNSSEC" -> Severity.LOW to "email_security"
        else -> return null // MX absence is not itself a spoofing weakness
    }
    val fix = when (c.name) {
        "SPF" -> "Publish an SPF TXT record listing authorized senders and ending in -all (hard fail)."
        "DMARC" -> "Publish a _dmarc TXT record with p=reject (or p=quarantine) plus rua reporting."
        "DKIM" -> "Generate a DKIM key, publish it at a selector and sign all outbound mail."
        "DNSSEC" -> "Enable DNSSEC at the registrar/zone so DNS answers are authenticated."
        else -> "Review the email-authentication configuration."
    }
    return Finding(
        id = "web-email-${c.name.lowercase()}-${host.hashCode().toUInt().toString(16)}",
        title = "Email spoofing posture: ${c.name} weak", category = cat, severity = sev,
        confidence = Confidence.CONFIRMED, target = host,
        evidence = mapOf("domain" to host, "check" to c.name),
        explanation = c.detail, remediation = fix,
        verification = Verification.VALIDATED_SAFELY, source = "web-assessment")
}

// ---- exporters ----

private fun esc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ")

private fun buildJson(target: String, findings: List<Pair<Finding, Cvss.Score>>): String {
    val items = findings.joinToString(",\n") { (f, c) ->
        """    {
      "title": "${esc(f.title)}",
      "severity": "${f.severity}",
      "cvss_base": ${"%.1f".format(c.base)},
      "cvss_vector": "${esc(c.vector)}",
      "confidence": "${f.confidence}",
      "category": "${esc(f.category)}",
      "target": "${esc(f.target)}",
      "explanation": "${esc(f.explanation)}",
      "remediation": "${esc(f.remediation)}"
    }"""
    }
    return """{
  "tool": "Packetra",
  "target": "${esc(target)}",
  "generated_at_epoch_ms": ${System.currentTimeMillis()},
  "findings": [
$items
  ]
}"""
}

/** SARIF 2.1.0 — consumable by GitHub code scanning and most CI security dashboards. */
private fun buildSarif(target: String, findings: List<Pair<Finding, Cvss.Score>>): String {
    fun level(s: Severity) = when (s) {
        Severity.CRITICAL, Severity.HIGH -> "error"
        Severity.MEDIUM, Severity.LOW -> "warning"
        Severity.INFO -> "note"
    }
    // Distinct rules by category.
    val rules = findings.map { it.first.category }.distinct().joinToString(",\n") { cat ->
        """        {
          "id": "${esc(cat)}",
          "name": "${esc(cat)}",
          "shortDescription": { "text": "${esc(cat)} finding" }
        }"""
    }
    val results = findings.joinToString(",\n") { (f, c) ->
        """      {
        "ruleId": "${esc(f.category)}",
        "level": "${level(f.severity)}",
        "message": { "text": "${esc(f.title)}. ${esc(f.explanation)} Fix: ${esc(f.remediation)}" },
        "properties": { "severity": "${f.severity}", "confidence": "${f.confidence}", "cvssBase": ${"%.1f".format(c.base)}, "cvssVector": "${esc(c.vector)}" },
        "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "${esc(f.target)}" } } } ]
      }"""
    }
    return """{
  "${'$'}schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Packetra",
          "informationUri": "https://github.com/n0obcoders/packetra",
          "version": "1.12.0",
          "rules": [
$rules
          ]
        }
      },
      "results": [
$results
      ]
    }
  ]
}"""
}

/** Structured Markdown suitable for pasting into a GitHub/GitLab issue. */
private fun buildMarkdown(target: String, findings: List<Pair<Finding, Cvss.Score>>): String {
    val sb = StringBuilder()
    sb.append("# Web assessment — ").append(target).append("\n\n")
    sb.append("_Generated by Packetra. CVSS scores are indicative base scores for triage, not final._\n\n")
    sb.append("## Summary\n\n")
    sb.append("| Severity | Count |\n|---|---|\n")
    Severity.entries.reversed().forEach { s ->
        val n = findings.count { it.first.severity == s }
        if (n > 0) sb.append("| ").append(s).append(" | ").append(n).append(" |\n")
    }
    sb.append("\n## Findings\n\n")
    if (findings.isEmpty()) sb.append("_No issues flagged._\n")
    findings.forEachIndexed { i, (f, c) ->
        sb.append("### ").append(i + 1).append(". ").append(f.title).append("\n\n")
        sb.append("- **Severity:** ").append(f.severity)
            .append(" · **CVSS:** ").append("%.1f".format(c.base)).append(" (").append(c.label).append(")")
            .append(" · **Confidence:** ").append(f.confidence).append("\n")
        sb.append("- **Category:** ").append(f.category).append("\n")
        sb.append("- **Target:** `").append(f.target).append("`\n")
        sb.append("- **CVSS vector:** `").append(c.vector).append("`\n")
        if (f.explanation.isNotBlank()) sb.append("- **Detail:** ").append(f.explanation).append("\n")
        if (f.remediation.isNotBlank()) sb.append("- **Remediation:** ").append(f.remediation).append("\n")
        val snippets = FixSnippets.forFinding(f)
        if (snippets != null) {
            sb.append("\n<details><summary>Platform fix snippets</summary>\n\n")
            snippets.forEach { (platform, block) ->
                sb.append("**").append(platform).append("**\n\n```\n").append(block).append("\n```\n\n")
            }
            sb.append("</details>\n")
        }
        sb.append("\n")
    }
    return sb.toString()
}

// ---- recon baseline (drift tracking) ----

private fun baselineFile(ctx: Context, host: String): java.io.File {
    val dir = java.io.File(ctx.filesDir, "recon-baselines").apply { mkdirs() }
    return java.io.File(dir, "bl-${host.lowercase().hashCode().toUInt().toString(16)}.txt")
}

/** Previous subdomain set for a host, or null if no baseline has been saved yet. */
private fun loadBaseline(ctx: Context, host: String): java.util.SortedSet<String>? = runCatching {
    val f = baselineFile(ctx, host)
    if (!f.exists()) null
    else f.readLines().map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSortedSet()
}.getOrNull()

private fun saveBaseline(ctx: Context, host: String, subs: java.util.SortedSet<String>) {
    runCatching { baselineFile(ctx, host).writeText(subs.joinToString("\n")) }
}

private fun saveFile(ctx: Context, prefix: String, ext: String, mime: String, content: String): String {
    val name = "$prefix-${System.currentTimeMillis()}.$ext"
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
            resolver.openOutputStream(uri)?.use { it.write(content.toByteArray()) } ?: return "Could not open output."
            values.clear(); values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
            "Saved $name to Downloads."
        } else {
            val dir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
            val f = java.io.File(dir, name); f.writeText(content)
            "Saved to ${f.absolutePath}"
        }
    } catch (t: Throwable) { "Export failed: ${t.message}" }
}

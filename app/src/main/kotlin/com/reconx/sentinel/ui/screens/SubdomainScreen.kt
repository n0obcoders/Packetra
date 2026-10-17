package com.reconx.sentinel.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.reconx.sentinel.feature.recon.SubdomainEngine
import com.reconx.sentinel.ui.SentinelViewModel

@Composable
fun SubdomainScreen(vm: SentinelViewModel) {
    // All state lives in the ViewModel cache, so results and the domain survive
    // navigating away and back — the screen never re-asks for the domain.
    var domain by vmState(vm, "sub.domain", "")
    var validate by vmState(vm, "sub.validate", true)
    var running by vmState(vm, "sub.running", false)
    var status by vmState(vm, "sub.status", "")
    val sources = vmList<String>(vm, "sub.sources")
    val subs = vmList<String>(vm, "sub.subs")

    ScreenColumn {
        SectionCard("Passive subdomain discovery (Sublist3r-style)") {
            Text("Queries public OSINT sources (crt.sh, hackertarget, certspotter, OTX, rapiddns, " +
                "urlscan, wayback, subdomain.center) — never the target itself. Failed/rate-limited " +
                "sources are shown, not hidden.",
                style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(domain, { domain = it }, label = { Text("Domain") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(validate, { validate = it }); Spacer(Modifier.width(8.dp)); Text("DNS-validate results")
            }
            Button(enabled = !running && domain.contains('.'), onClick = {
                running = true; status = "Querying sources…"; sources.clear(); subs.clear()
                val d = domain.trim(); val doValidate = validate
                // Runs on the ViewModel scope: keeps going if the user leaves the
                // screen, and does not block other screens' work.
                vm.vmLaunch {
                    try {
                        val r = SubdomainEngine(vm.dispatchers).discover(d, doValidate)
                        r.sources.forEach { s ->
                            sources.add("${s.name}: ${s.found}${s.error?.let { "  ($it)" } ?: ""}")
                        }
                        r.subs.forEach { s ->
                            val mark = if (!doValidate) "·" else if (s.resolved) "✓" else "✗"
                            val ips = if (s.addresses.isNotEmpty()) "  ${s.addresses.joinToString(",")}" else ""
                            subs.add("$mark ${s.host}  [${s.sources.joinToString("+")}]$ips")
                        }
                        status = "${r.subs.size} unique subdomains" +
                            if (r.wildcard) " · ⚠ wildcard DNS detected (validate carefully)" else ""
                    } catch (t: Throwable) {
                        status = "Failed: ${t.message ?: t.javaClass.simpleName}"
                    } finally {
                        running = false
                    }
                }
            }) { Text(if (running) "Discovering…" else "Discover") }
            if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
        }
        if (sources.isNotEmpty()) SectionCard("Sources") { sources.forEach { Mono(it) } }
        if (subs.isNotEmpty()) CopyableResults("Subdomains (${subs.size})", subs.toList())
    }
}

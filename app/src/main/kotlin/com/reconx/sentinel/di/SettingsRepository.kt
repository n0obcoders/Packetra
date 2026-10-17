package com.reconx.sentinel.di

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.reconx.sentinel.core.security.EngagementStatus
import com.reconx.sentinel.feature.capture.FirewallRules
import com.reconx.sentinel.feature.capture.ProxyConfig
import com.reconx.sentinel.ui.EngagementState
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore("sentinel_settings")

/**
 * Persists the operator's own settings so they survive an app restart:
 *  - the ReconX base URL (DataStore, unchanged);
 *  - the engagement **scope** (targets/CIDRs/exclusions);
 *  - the capture **proxy** config and **firewall** rules.
 *
 * Scope/proxy/firewall are small, read once at startup and on save, so they live
 * in a simple SharedPreferences file (synchronous, no suspend needed at the call
 * sites that restore them). The live *captured packets* are deliberately NOT
 * persisted — a capture is session-only; only an exported PCAP keeps its data.
 */
class SettingsRepository(private val context: Context) {
    private val reconxUrlKey = stringPreferencesKey("reconx_base_url")
    private val prefs = context.getSharedPreferences("packetra_settings", Context.MODE_PRIVATE)

    val reconxBaseUrl: Flow<String> =
        context.dataStore.data.map { it[reconxUrlKey] ?: "" }

    suspend fun setReconxBaseUrl(url: String) {
        context.dataStore.edit { it[reconxUrlKey] = url.trim() }
    }

    // ---- Engagement scope -------------------------------------------------

    fun loadEngagement(): EngagementState {
        if (!prefs.getBoolean("eng_saved", false)) return EngagementState()
        return EngagementState(
            name = prefs.getString("eng_name", "") ?: "",
            clientLabel = prefs.getString("eng_client", "") ?: "",
            status = runCatching { EngagementStatus.valueOf(prefs.getString("eng_status", "") ?: "") }
                .getOrDefault(EngagementStatus.DRAFT),
            domains = prefs.getString("eng_domains", "").toLines(),
            cidrs = prefs.getString("eng_cidrs", "").toLines(),
            exclusions = prefs.getString("eng_exclusions", "").toLines(),
            labConfirmed = prefs.getBoolean("eng_lab", true),
        )
    }

    fun saveEngagement(e: EngagementState) {
        prefs.edit()
            .putBoolean("eng_saved", true)
            .putString("eng_name", e.name)
            .putString("eng_client", e.clientLabel)
            .putString("eng_status", e.status.name)
            .putString("eng_domains", e.domains.joinToString("\n"))
            .putString("eng_cidrs", e.cidrs.joinToString("\n"))
            .putString("eng_exclusions", e.exclusions.joinToString("\n"))
            .putBoolean("eng_lab", e.labConfirmed)
            .apply()
    }

    // ---- Capture proxy ----------------------------------------------------

    fun loadProxy(): ProxyConfig = runCatching {
        ProxyConfig(
            type = ProxyConfig.Type.valueOf(prefs.getString("proxy_type", "NONE") ?: "NONE"),
            host = prefs.getString("proxy_host", "") ?: "",
            port = prefs.getInt("proxy_port", 0),
            username = prefs.getString("proxy_user", "")?.ifBlank { null },
            password = prefs.getString("proxy_pass", "")?.ifBlank { null },
        )
    }.getOrDefault(ProxyConfig())

    fun saveProxy(c: ProxyConfig) {
        prefs.edit()
            .putString("proxy_type", c.type.name)
            .putString("proxy_host", c.host)
            .putInt("proxy_port", c.port)
            .putString("proxy_user", c.username ?: "")
            .putString("proxy_pass", c.password ?: "")
            .apply()
    }

    // ---- Capture firewall -------------------------------------------------

    fun loadFirewall(): FirewallRules {
        if (!prefs.getBoolean("fw_saved", false)) return FirewallRules()
        val apps = (prefs.getString("fw_apps", "") ?: "").toLines()
            .mapNotNull { FirewallRules.parseAppRule(it, FirewallRules.Proto.BOTH) }.toSet()
        return FirewallRules(
            blockedApps = apps,
            blockedDomains = (prefs.getString("fw_domains", "") ?: "").toLines().toSet(),
            blockedIps = (prefs.getString("fw_ips", "") ?: "").toLines().toSet(),
            enabled = prefs.getBoolean("fw_enabled", false),
        )
    }

    fun saveFirewall(r: FirewallRules) {
        val appLines = r.blockedApps.joinToString("\n") {
            if (it.proto == FirewallRules.Proto.BOTH) it.match else "${it.match}:${it.proto.name.lowercase()}"
        }
        prefs.edit()
            .putBoolean("fw_saved", true)
            .putString("fw_apps", appLines)
            .putString("fw_domains", r.blockedDomains.joinToString("\n"))
            .putString("fw_ips", r.blockedIps.joinToString("\n"))
            .putBoolean("fw_enabled", r.enabled)
            .apply()
    }

    private fun String?.toLines(): List<String> =
        (this ?: "").split('\n').map { it.trim() }.filter { it.isNotEmpty() }
}

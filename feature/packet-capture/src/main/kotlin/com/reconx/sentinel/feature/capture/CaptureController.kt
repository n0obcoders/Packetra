package com.reconx.sentinel.feature.capture

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Process-wide bridge between the [SentinelVpnService] and the UI. The service
 * is the single writer of live data; the Compose screen observes these flows and
 * also sets firewall / blocklist / PCAP-over-IP controls that the running capture
 * reads live. Nothing here is persisted — a capture is a user-initiated session.
 */
object CaptureController {
    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _stats = MutableStateFlow(CaptureStats(false, 0, 0, 0, null))
    val stats: StateFlow<CaptureStats> = _stats.asStateFlow()

    private val _flows = MutableStateFlow<List<ConnectionFlow>>(emptyList())
    val flows: StateFlow<List<ConnectionFlow>> = _flows.asStateFlow()

    private val _dns = MutableStateFlow<List<DnsEvent>>(emptyList())
    val dns: StateFlow<List<DnsEvent>> = _dns.asStateFlow()

    private val _appUsage = MutableStateFlow<List<AppUsage>>(emptyList())
    val appUsage: StateFlow<List<AppUsage>> = _appUsage.asStateFlow()

    // ---- Firewall (read live by the running capture) ----
    private val _firewall = MutableStateFlow(FirewallRules())
    val firewall: StateFlow<FirewallRules> = _firewall.asStateFlow()
    fun setFirewall(rules: FirewallRules) { _firewall.value = rules }
    fun firewallRules(): FirewallRules = _firewall.value

    // ---- Malware/tracker blocklist ----
    @Volatile private var _blocklist = Blocklist()
    fun blocklist(): Blocklist = _blocklist
    private val _blocklistCount = MutableStateFlow(0)
    val blocklistCount: StateFlow<Int> = _blocklistCount.asStateFlow()
    fun loadBlocklist(lines: Sequence<String>) {
        val b = Blocklist(); b.loadLines(lines); _blocklist = b; _blocklistCount.value = b.size()
    }
    fun clearBlocklist() { _blocklist = Blocklist(); _blocklistCount.value = 0 }

    // ---- Upstream proxy for captured TCP flows (read live by the capture) ----
    private val _proxy = MutableStateFlow(ProxyConfig())
    val proxy: StateFlow<ProxyConfig> = _proxy.asStateFlow()
    fun setProxy(cfg: ProxyConfig) { _proxy.value = cfg }
    fun proxyConfig(): ProxyConfig = _proxy.value

    // ---- PCAP-over-IP (stream to Wireshark: TCP@<device-ip>:port) ----
    private val _pcapOverIp = MutableStateFlow(false)
    val pcapOverIp: StateFlow<Boolean> = _pcapOverIp.asStateFlow()
    const val pcapOverIpPort = 9922
    fun setPcapOverIp(on: Boolean) { _pcapOverIp.value = on }

    @Volatile var lastPcapPath: String? = null; internal set

    internal fun setRunning(r: Boolean) { _running.value = r }
    internal fun publishStats(s: CaptureStats) { _stats.value = s }
    internal fun publishFlows(f: List<ConnectionFlow>) { _flows.value = f }
    internal fun publishAppUsage(u: List<AppUsage>) { _appUsage.value = u }
    internal fun addDns(e: DnsEvent) { _dns.value = (listOf(e) + _dns.value).take(200) }
    internal fun clear() { _flows.value = emptyList(); _dns.value = emptyList(); _appUsage.value = emptyList() }
}

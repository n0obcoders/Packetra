package com.reconx.sentinel.feature.netdiscovery

import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.security.ScopeValidator
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

/**
 * Network scanner supporting TCP connect, UDP probe and host-discovery (ping
 * sweep) modes — the techniques achievable on non-root Android. Every target is
 * scope-validated before a single packet is sent. SYN/stealth scanning needs
 * root (CAP_NET_RAW) and is deliberately not offered; timing templates only
 * control speed on authorized targets.
 */
class TcpConnectScanner(
    private val scope: ScopeValidator,
    private val dispatchers: DispatcherProvider,
) {
    fun scan(host: String, config: ScanConfig): Flow<ScanEvent> = channelFlow {
        val target = host.trim()
        val decision = scope.validate(target)
        if (!decision.allowed) { send(ScanEvent.Failed("refused: ${decision.reason}")); return@channelFlow }

        val ip = withContext(dispatchers.io) {
            runCatching { InetAddress.getByName(target).hostAddress }.getOrNull()
        }
        if (ip == null) { send(ScanEvent.Failed("could not resolve '$target' (DNS lookup failed)")); return@channelFlow }

        val t = config.timing
        // Host discovery
        if (config.scanType == ScanType.PING_SWEEP || config.hostDiscovery) {
            val up = withContext(dispatchers.io) { hostIsUp(ip, t.connectTimeoutMs) }
            send(ScanEvent.Host(up, "tcp-ping 80/443/22/25"))
            if (config.scanType == ScanType.PING_SWEEP) {
                send(ScanEvent.Done(0, 0, 0, 0, 0)); return@channelFlow
            }
            if (!up && !config.hostDiscovery) { /* -Pn would skip; here discovery ran */ }
        }

        val ports = config.ports
        send(ScanEvent.Resolved(target, ip, ports.size))
        val started = System.currentTimeMillis()
        val gate = Semaphore(t.concurrency)
        val results = Channel<PortResult>(Channel.UNLIMITED)

        coroutineScope {
            launch {
                for (port in ports) {
                    launch(dispatchers.io) {
                        gate.withPermit {
                            if (t.perProbeDelayMs > 0) delay(t.perProbeDelayMs)
                            results.send(probe(ip, target, port, config))
                        }
                    }
                }
            }
            var scanned = 0; var open = 0; var closed = 0; var filtered = 0
            while (scanned < ports.size) {
                val r = results.receive(); scanned++
                when (r.state) {
                    PortState.OPEN -> { open++; send(ScanEvent.Open(r)) }
                    PortState.CLOSED -> closed++
                    PortState.FILTERED -> filtered++
                }
                if (scanned % 25 == 0 || scanned == ports.size)
                    send(ScanEvent.Progress(scanned, ports.size, open))
            }
            results.close()
            send(ScanEvent.Done(scanned, open, closed, filtered, System.currentTimeMillis() - started))
        }
    }

    private fun hostIsUp(ip: String, timeoutMs: Int): Boolean =
        intArrayOf(80, 443, 22, 25).any { port ->
            try { Socket().use { it.connect(InetSocketAddress(ip, port), timeoutMs); true } }
            catch (e: java.net.ConnectException) { true } // RST = host reachable
            catch (e: Throwable) { false }
        }

    private suspend fun probe(ip: String, host: String, port: Int, config: ScanConfig): PortResult =
        withContext(dispatchers.io) {
            if (config.scanType == ScanType.UDP) {
                val state = UdpProbe.probe(ip, port, config.timing.connectTimeoutMs)
                return@withContext PortResult(host, port, state, null, WellKnownPorts.service(port))
            }
            val start = System.currentTimeMillis()
            try {
                Socket().use { s -> s.connect(InetSocketAddress(ip, port), config.timing.connectTimeoutMs) }
                val ms = System.currentTimeMillis() - start
                val service = WellKnownPorts.service(port)
                val det = if (config.serviceDetection)
                    ServiceDetector.detect(ip, port, service, config.timing.connectTimeoutMs)
                    else ServiceDetector.Detected(null, null)
                PortResult(host, port, PortState.OPEN, ms, service, det.product, det.banner)
            } catch (e: java.net.SocketTimeoutException) {
                PortResult(host, port, PortState.FILTERED, null, null)
            } catch (e: Throwable) {
                PortResult(host, port, PortState.CLOSED, null, null)
            }
        }

    suspend fun scanHost(host: String, config: ScanConfig): HostScanResult {
        val decision = scope.validate(host)
        if (!decision.allowed)
            return HostScanResult(host, null, emptyList(), reachable = false, error = decision.reason)
        val ip = withContext(dispatchers.io) {
            runCatching { InetAddress.getByName(host).hostAddress }.getOrNull()
        } ?: return HostScanResult(host, null, emptyList(), reachable = false, error = "DNS failed")
        val results = mutableListOf<PortResult>()
        for (port in config.ports)
            probe(ip, host, port, config).takeIf { it.state == PortState.OPEN }?.let { results.add(it) }
        return HostScanResult(host, ip, results, reachable = results.isNotEmpty())
    }
}

/** IANA well-known port → service NAME map. A label only; never a vuln claim. */
object WellKnownPorts {
    private val map = mapOf(
        21 to "ftp", 22 to "ssh", 23 to "telnet", 25 to "smtp", 53 to "dns",
        67 to "dhcp", 69 to "tftp", 80 to "http", 110 to "pop3", 123 to "ntp",
        137 to "netbios", 143 to "imap", 161 to "snmp", 389 to "ldap", 443 to "https",
        445 to "smb", 500 to "ike", 587 to "smtp-submission", 636 to "ldaps",
        993 to "imaps", 995 to "pop3s", 1433 to "mssql", 1521 to "oracle",
        1900 to "ssdp", 2049 to "nfs", 3306 to "mysql", 3389 to "rdp",
        5353 to "mdns", 5432 to "postgresql", 5900 to "vnc", 6379 to "redis",
        8080 to "http-alt", 8443 to "https-alt", 8000 to "http-alt", 8888 to "http-alt",
        9200 to "elasticsearch", 11211 to "memcached", 27017 to "mongodb",
    )
    fun service(port: Int): String? = map[port]
}

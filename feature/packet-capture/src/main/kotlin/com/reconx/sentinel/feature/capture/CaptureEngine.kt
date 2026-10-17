package com.reconx.sentinel.feature.capture

import java.util.concurrent.ConcurrentHashMap

/**
 * Wires the read loop to the forwarders, the flow tracker, the DNS parser and
 * the PCAP writer(s). Handles IPv4 TCP/UDP (forwarded + tracked); other protocols
 * are counted. Enriches flows with TLS SNI and cleartext HTTP host (no
 * decryption), offline ASN/country, and enforces the on-device firewall by
 * dropping blocked connections — for BOTH TCP and UDP, so app/VoIP traffic
 * (e.g. a WhatsApp call, which is UDP) is actually blocked. The VpnService
 * routes only IPv4.
 */
class CaptureEngine(
    tun: TunWriter,
    socketProtect: SocketProtector,
    datagramProtect: DatagramProtector,
    val pcap: PacketSink?,
    private val onDns: (DnsEvent) -> Unit,
    appResolver: ((ConnKey) -> String?)? = null,
    asnLookup: ((String) -> AsnLookup.Geo?)? = null,
    private val firewall: (() -> FirewallRules)? = null,
    blocklist: (() -> Blocklist)? = null,
    // Optional upstream proxy for captured TCP flows (plain routing, no decryption).
    proxy: (() -> ProxyConfig)? = null,
) {
    val tracker = ConnectionTracker(appResolver, asnLookup, firewall, blocklist)
    private val dnsMap = ConcurrentHashMap<String, String>()
    private val appResolverRef = appResolver
    private val blocklistRef = blocklist

    // Per-flow firewall decision cache. Resolving a connection's owning app is a
    // kernel lookup, so we do it once per flow and reuse the verdict; the cache
    // is cleared whenever the rules or the blocklist change so new rules take
    // effect immediately on the next packet (including for in-flight flows).
    private val blockCache = ConcurrentHashMap<String, Boolean>()
    @Volatile private var lastFw: FirewallRules? = null
    @Volatile private var lastBlocklist: Blocklist? = null

    private val udp = UdpForwarder(tun, datagramProtect,
        onFlow = { k, n, out -> tracker.record(k, n, out, dnsMap[k.dstIp]) },
        onDnsPayload = { b, off, len -> handleDns(b, off, len) },
        onPayload = { k, b, off, len, out -> tracker.classify(k, b, off, len, out) })

    private val tcp = TcpForwarder(tun, socketProtect,
        onFlow = { k, n, out -> tracker.record(k, n, out, dnsMap[k.dstIp]) },
        onPayload = { k, b, off, len, out -> tracker.classify(k, b, off, len, out) },
        proxy = proxy ?: { ProxyConfig() })

    fun onPacket(buf: ByteArray, len: Int) {
        pcap?.write(buf, len)
        if (IpPacket.version(buf, len) != 4) return
        val ip = IpPacket.parseV4(buf, len) ?: return
        val sport = IpPacket.u16(buf, ip.ihl)
        val dport = IpPacket.u16(buf, ip.ihl + 2)
        val srcIp = IpPacket.ipToString(ip.src)
        val dstIp = IpPacket.ipToString(ip.dst)
        when (ip.proto) {
            IpPacket.PROTO_TCP -> {
                annotateTcp(ip, buf, len)
                val key = ConnKey("TCP", srcIp, sport, dstIp, dport)
                if (dropIfBlocked(key, dstIp, len)) { tcp.drop(key); return }
                tcp.handle(ip, buf, len)
                tracker.sample(key, buf, len)
            }
            IpPacket.PROTO_UDP -> {
                val key = ConnKey("UDP", srcIp, sport, dstIp, dport)
                if (dropIfBlocked(key, dstIp, len)) { udp.drop(key); return }
                udp.handle(ip, buf, len)
                tracker.sample(key, buf, len)
            }
            else -> { /* ICMP/other: counted via pcap, not forwarded */ }
        }
    }

    /** Extracts TLS SNI / cleartext HTTP host and annotates the flow (no drop). */
    private fun annotateTcp(ip: IpPacket.V4, buf: ByteArray, len: Int) {
        val sport = IpPacket.u16(buf, ip.ihl)
        val dport = IpPacket.u16(buf, ip.ihl + 2)
        val key = ConnKey("TCP", IpPacket.ipToString(ip.src), sport, IpPacket.ipToString(ip.dst), dport)
        // Once the flow's hostname is known there is nothing more to extract, so skip
        // the SNI/HTTP parse on every subsequent packet of the same flow. This is the
        // main per-packet CPU cost on a long transfer (e.g. a big upload over a proxy).
        if (!tracker.annotationNeeded(key)) return
        val payloadLen = (ip.totalLen - ip.payloadOff).coerceIn(0, len - ip.payloadOff)
        if (payloadLen > 0) {
            val sni = runCatching { TlsParser.extractSni(buf, ip.payloadOff, payloadLen) }.getOrNull()
            val http = runCatching { HttpParser.parseRequest(buf, ip.payloadOff, payloadLen) }.getOrNull()
            if (sni != null || http != null)
                tracker.annotate(key, sni, http?.host, http?.method, http?.path)
        }
    }

    /**
     * True if this packet's flow is blocked by the firewall or the malware/tracker
     * blocklist, in which case the caller drops it (does not forward). Resolves the
     * owning app on first sight so app-name rules work from the very first packet,
     * and re-tries resolution while an app rule exists but the app is not yet known.
     */
    private fun dropIfBlocked(key: ConnKey, dstIp: String, pktLen: Int): Boolean {
        val fw = firewall?.invoke()
        val bl = blocklistRef?.invoke()
        if (fw != lastFw || bl !== lastBlocklist) { lastFw = fw; lastBlocklist = bl; blockCache.clear() }
        if (fw == null || !fw.enabled) return false

        val ck = key.toString()
        blockCache[ck]?.let { cached ->
            if (cached) tracker.record(key, pktLen, true, dnsMap[dstIp]) // reflect attempted bytes
            return cached
        }

        val existing = tracker.flow(key)
        val appLabel = existing?.appLabel ?: runCatching { appResolverRef?.invoke(key) }.getOrNull()
        val host = existing?.host ?: existing?.sni ?: existing?.httpHost ?: dnsMap[dstIp]
        val blocked = fw.decide(appLabel, host, dstIp, key.proto).blocked || (bl?.isListed(host) == true)

        // App not resolved yet but an app rule exists: don't cache a false verdict,
        // re-evaluate on the next packet once the kernel knows the owner.
        if (!blocked && appLabel == null && fw.blockedApps.isNotEmpty()) return false

        blockCache[ck] = blocked
        if (blocked) { tracker.record(key, pktLen, true, host); tracker.markBlocked(key) }
        return blocked
    }

    private fun handleDns(buf: ByteArray, off: Int, len: Int) {
        val dns = DnsPacketParser.parse(buf, off, len) ?: return
        dns.queries.forEach { onDns(DnsEvent(it)) }
        dns.answers.forEach { (ip, host) ->
            dnsMap[ip] = host
            tracker.annotateHost(ip, host)
        }
    }

    fun shutdown() { udp.closeAll(); tcp.closeAll(); runCatching { pcap?.close() } }
}

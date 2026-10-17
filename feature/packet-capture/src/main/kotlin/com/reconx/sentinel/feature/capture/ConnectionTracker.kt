package com.reconx.sentinel.feature.capture

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Aggregates per-connection byte counters and metadata. Pure logic (no Android),
 * fed by the forwarders with each packet's direction and length, so it is
 * unit-testable. App attribution, offline ASN/country, firewall and blocklist
 * checks are injected so the tracker stays pure and the lookups are done once per
 * flow (when first seen), not per packet.
 *
 * Performance: each live flow is a single long-lived [MutableFlow] object kept in
 * a concurrent map. A packet update mutates counters in place under a tiny
 * per-flow lock — it allocates nothing, so capturing thousands of packets per
 * second does not churn the garbage collector. Immutable [ConnectionFlow]
 * snapshots are built only when the UI reads ([snapshot], [flow]). A monotonic
 * [revision] lets the capture service skip publishing when nothing changed.
 */
class ConnectionTracker(
    private val appResolver: ((ConnKey) -> String?)? = null,
    private val asnLookup: ((String) -> AsnLookup.Geo?)? = null,
    private val firewall: (() -> FirewallRules)? = null,
    private val blocklist: (() -> Blocklist)? = null,
) {
    private val flows = ConcurrentHashMap<String, MutableFlow>()
    private val rev = AtomicLong(0)
    @Volatile var packets: Long = 0; private set
    @Volatile var bytes: Long = 0; private set
    @Volatile var blockedCount: Long = 0; private set

    /** Monotonic counter bumped on every mutation; lets a reader detect "no change". */
    fun revision(): Long = rev.get()

    fun record(key: ConnKey, len: Int, outbound: Boolean, host: String?) {
        packets++; bytes += len
        val f = flows.computeIfAbsent(key.toString()) { newFlow(key, host) }
        synchronized(f) {
            if (host != null && f.host == null) { f.host = host; evaluateRules(f) }
            f.packets += 1
            if (outbound) f.bytesOut += len else f.bytesIn += len
            f.lastSeenEpochMs = System.currentTimeMillis()
        }
        rev.incrementAndGet()
    }

    /**
     * Stash the first observed packet's raw bytes (capped) on the flow so the UI
     * can render a hex dump. Captured once per flow; the flow must already exist
     * (record() runs first). These are the exact bytes seen on the TUN — the same
     * data PCAP writes — never decrypted or synthesised.
     */
    fun sample(key: ConnKey, buf: ByteArray, len: Int) {
        if (len <= 0) return
        val f = flows[key.toString()] ?: return
        synchronized(f) {
            if (f.sampleBytes == null) {
                val n = minOf(len, SAMPLE_CAP)
                f.sampleBytes = buf.copyOf(n); f.sampleLen = n
            }
        }
        rev.incrementAndGet()
    }

    private fun newFlow(key: ConnKey, host: String?): MutableFlow {
        val app = runCatching { appResolver?.invoke(key) }.getOrNull()
        val geo = runCatching { asnLookup?.invoke(key.dstIp) }.getOrNull()
        val f = MutableFlow(key.proto, key.srcPort, key.dstIp, key.dstPort).apply {
            this.host = host; appLabel = app; asn = geo?.asn; org = geo?.org; country = geo?.country
        }
        evaluateRules(f)
        return f
    }

    /**
     * Deep-packet-inspection hook: classify the L7 protocol from the first
     * outbound payload and detect carried content from cleartext (request or the
     * first inbound/response payload). Stores a capped inbound sample so the UI
     * can show what the server actually sent. Never decrypts — an encrypted flow
     * is simply marked encrypted with no content.
     */
    fun classify(key: ConnKey, payload: ByteArray, off: Int, len: Int, outbound: Boolean) {
        if (len <= 0) return
        val f = flows[key.toString()] ?: return
        synchronized(f) {
            if (outbound && f.l7 == null) {
                runCatching { DpiClassifier.classify(payload, off, len, key.dstPort, key.proto) }.getOrNull()
                    ?.let { l7 ->
                        f.l7 = l7.detail?.let { "${l7.protocol} · $it" } ?: l7.protocol
                        f.encrypted = l7.encrypted
                    }
            }
            if (f.contentType == null && !f.encrypted) {
                runCatching { ContentTypeDetector.sniff(payload, off, len) }.getOrNull()
                    ?.let { kind -> f.contentType = kind.label }
            }
            if (!outbound && f.respSampleBytes == null) {
                val n = minOf(len, SAMPLE_CAP)
                f.respSampleBytes = payload.copyOfRange(off, off + n); f.respSampleLen = n
            }
        }
        rev.incrementAndGet()
    }

    /** Adds host info learned from TLS SNI / cleartext HTTP, re-checking rules. */
    fun annotate(key: ConnKey, sni: String?, httpHost: String?,
                 httpMethod: String? = null, httpPath: String? = null) {
        val f = flows[key.toString()] ?: return
        synchronized(f) {
            if (sni != null) f.sni = sni
            if (httpHost != null) f.httpHost = httpHost
            if (httpMethod != null) f.httpMethod = httpMethod
            if (httpPath != null) f.httpPath = httpPath
            if (f.host == null) f.host = f.sni ?: f.httpHost
            evaluateRules(f)
        }
        rev.incrementAndGet()
    }

    /** Must be called while holding the flow's monitor. */
    private fun evaluateRules(f: MutableFlow) {
        val effectiveHost = f.host ?: f.sni ?: f.httpHost
        f.malicious = runCatching { blocklist?.invoke()?.isListed(effectiveHost) }.getOrNull() ?: false
        runCatching { firewall?.invoke()?.decide(f.appLabel, effectiveHost, f.dstIp, f.proto) }
            .getOrNull()?.let { f.blocked = it.blocked }
    }

    /** True if a new connection should be dropped (not forwarded) by firewall/blocklist. */
    fun shouldBlock(appLabel: String?, host: String?, ip: String, proto: String? = null): Boolean =
        runCatching { firewall?.invoke()?.decide(appLabel, host, ip, proto)?.blocked }.getOrNull() ?: false

    fun markBlocked(key: ConnKey) {
        blockedCount++
        flows[key.toString()]?.let { f -> synchronized(f) { f.blocked = true } }
        rev.incrementAndGet()
    }

    /** Back-fill a hostname onto existing flows once DNS reveals it. */
    fun annotateHost(ip: String, host: String) {
        var changed = false
        for (f in flows.values) {
            if (f.dstIp == ip) synchronized(f) {
                if (f.host == null) { f.host = host; evaluateRules(f); changed = true }
            }
        }
        if (changed) rev.incrementAndGet()
    }

    fun flow(key: ConnKey): ConnectionFlow? = flows[key.toString()]?.let { synchronized(it) { it.toFlow() } }

    /**
     * Hot-path check (allocates nothing): is this flow still missing a hostname, so
     * the engine should keep trying to extract TLS SNI / HTTP host from its packets?
     * Once both are known we stop parsing every packet of a long transfer — the
     * biggest per-packet CPU saving for bulk flows (e.g. a large upload via proxy).
     */
    fun annotationNeeded(key: ConnKey): Boolean {
        val f = flows[key.toString()] ?: return true
        return synchronized(f) { f.sni == null || (f.httpHost == null && f.httpMethod == null) }
    }

    /**
     * Newest-first immutable snapshot, capped to [limit] flows so the UI never has
     * to lay out an unbounded list. The newest flows (by last-seen) are the ones a
     * user watches, so older idle flows are dropped from the view first.
     */
    fun snapshot(limit: Int = Int.MAX_VALUE): List<ConnectionFlow> {
        val values = flows.values
        val sorted = values.sortedByDescending { it.lastSeenEpochMs }
        val capped = if (sorted.size > limit) sorted.subList(0, limit) else sorted
        return capped.map { f -> synchronized(f) { f.toFlow() } }
    }

    /** Per-app rollup of data usage, highest total first (capped). */
    fun appUsage(limit: Int = Int.MAX_VALUE): List<AppUsage> {
        val agg = HashMap<String, long4>()
        for (f in flows.values) synchronized(f) {
            val a = agg.getOrPut(f.appLabel ?: "unknown") { long4() }
            a.out += f.bytesOut; a.`in` += f.bytesIn; a.conns += 1; a.pkts += f.packets
        }
        val list = agg.map { (app, a) -> AppUsage(app, a.out, a.`in`, a.conns, a.pkts) }
            .sortedByDescending { it.bytesOut + it.bytesIn }
        return if (list.size > limit) list.subList(0, limit) else list
    }

    fun size() = flows.size
    fun reset() { flows.clear(); packets = 0; bytes = 0; blockedCount = 0; rev.set(0) }

    /** Scratch accumulator for [appUsage]; avoids five boxed longs per app. */
    private class long4 { var out = 0L; var `in` = 0L; var conns = 0; var pkts = 0L }

    /** Mutable backing store for one flow. All field access is under `synchronized(this)`. */
    private class MutableFlow(
        val proto: String, val srcPort: Int, val dstIp: String, val dstPort: Int,
    ) {
        var host: String? = null
        var appLabel: String? = null
        var sni: String? = null
        var httpHost: String? = null
        var httpMethod: String? = null
        var httpPath: String? = null
        var asn: String? = null
        var org: String? = null
        var country: String? = null
        var l7: String? = null
        var encrypted: Boolean = false
        var contentType: String? = null
        var blocked: Boolean = false
        var malicious: Boolean = false
        var packets: Long = 0
        var bytesOut: Long = 0
        var bytesIn: Long = 0
        val firstSeenEpochMs: Long = System.currentTimeMillis()
        var lastSeenEpochMs: Long = System.currentTimeMillis()
        var sampleBytes: ByteArray? = null
        var sampleLen: Int = 0
        var respSampleBytes: ByteArray? = null
        var respSampleLen: Int = 0

        fun toFlow() = ConnectionFlow(
            protocol = proto, srcPort = srcPort, destIp = dstIp, destPort = dstPort,
            host = host, appLabel = appLabel, sni = sni, httpHost = httpHost,
            httpMethod = httpMethod, httpPath = httpPath, asn = asn, org = org, country = country,
            l7 = l7, encrypted = encrypted, contentType = contentType, blocked = blocked,
            malicious = malicious, packets = packets, bytesOut = bytesOut, bytesIn = bytesIn,
            firstSeenEpochMs = firstSeenEpochMs, lastSeenEpochMs = lastSeenEpochMs,
            sampleBytes = sampleBytes, sampleLen = sampleLen,
            respSampleBytes = respSampleBytes, respSampleLen = respSampleLen,
        )
    }

    companion object { const val SAMPLE_CAP = 1024 }
}

package com.reconx.sentinel.feature.capture

/** One observed connection flow (metadata — headers and byte counts, never
 *  decrypted payload). */
data class ConnectionFlow(
    val protocol: String,     // TCP | UDP
    val srcPort: Int,
    val destIp: String,
    val destPort: Int,
    val host: String? = null, // resolved from observed DNS, if known
    val appLabel: String? = null, // owning app (uid→package), best-effort, API 29+
    val sni: String? = null,      // TLS ClientHello server_name (no decryption)
    val httpHost: String? = null, // cleartext HTTP Host header
    val httpMethod: String? = null, // cleartext HTTP request method (e.g. GET)
    val httpPath: String? = null,   // cleartext HTTP request path
    val asn: String? = null,      // offline ASN lookup of the remote IP
    val org: String? = null,      // offline network/org of the remote IP (location)
    val country: String? = null,  // offline country CODE of the remote IP
    val l7: String? = null,       // DPI-detected app-layer protocol (TLS/HTTP/DNS/QUIC…)
    val encrypted: Boolean = false, // DPI says the payload is ciphertext (no content sniff)
    val contentType: String? = null, // carried content detected on cleartext (Image/Video/PDF/Text…)
    val blocked: Boolean = false, // dropped by a firewall rule
    val malicious: Boolean = false, // host on a loaded blocklist
    val packets: Long = 0,
    val bytesOut: Long = 0,
    val bytesIn: Long = 0,
    val firstSeenEpochMs: Long = System.currentTimeMillis(),
    val lastSeenEpochMs: Long = System.currentTimeMillis(),
    // First observed packet of the flow (raw IP bytes, capped), for a hex dump.
    // Never decrypted payload — just what crossed the TUN, same as PCAP.
    val sampleBytes: ByteArray? = null,
    val sampleLen: Int = 0,
    // First observed INBOUND L4 payload (capped), so the UI can show/sniff what the
    // server sent back. Cleartext only reveals content; TLS/QUIC stays ciphertext.
    val respSampleBytes: ByteArray? = null,
    val respSampleLen: Int = 0,
) {
    // ByteArray in a data class breaks structural equality; flows are keyed by
    // ConnKey in a map, never compared by value, so identity equality is correct
    // and avoids deep-copying the sample on every hashable use.
    override fun equals(other: Any?): Boolean = this === other
    override fun hashCode(): Int = System.identityHashCode(this)
}

data class CaptureStats(
    val running: Boolean,
    val flows: Int,
    val packets: Long,
    val bytes: Long,
    val startedAtEpochMs: Long?,
    val pcapPackets: Long = 0,
    val blocked: Long = 0,
    val pcapOverIpClients: Int = 0,
)

data class DnsEvent(val name: String, val atEpochMs: Long = System.currentTimeMillis())

/** Per-app data usage aggregated across that app's connections. */
data class AppUsage(
    val app: String,
    val bytesOut: Long,
    val bytesIn: Long,
    val connections: Int,
    val packets: Long = 0,
)

package com.reconx.sentinel.feature.netdiscovery

/**
 * nmap-style scan configuration: timing template, port specification, and
 * optional service/version detection. The scope firewall (checked by the
 * scanner before any connection) is independent of this and cannot be disabled
 * here — this type only controls HOW FAST and WHICH ports an *authorized*
 * target is scanned.
 */
data class ScanConfig(
    val timing: Timing = Timing.T3,
    val ports: List<Int> = ScanProfile.COMMON.ports,
    val serviceDetection: Boolean = true,
    val portLabel: String = "common",
    val scanType: ScanType = ScanType.TCP_CONNECT,
    /** Host discovery before the port scan. -Pn (treat host as up) sets false. */
    val hostDiscovery: Boolean = true,
)

/**
 * Scan techniques actually implementable on non-root Android:
 *  - TCP_CONNECT  full connect() scan (nmap -sT)
 *  - UDP          datagram probes with protocol payloads (nmap -sU); results are
 *                 OPEN (reply seen) or OPEN|FILTERED (no reply — honest, since we
 *                 cannot read ICMP port-unreachable without root)
 *  - PING_SWEEP   host discovery only (nmap -sn): TCP pings to common ports
 * SYN/stealth scans need CAP_NET_RAW (root) and are intentionally NOT offered.
 */
enum class ScanType { TCP_CONNECT, UDP, PING_SWEEP }

/**
 * Timing templates mirror nmap's -T0..-T5. They set the concurrency (how many
 * sockets are opened at once) and the per-probe connect timeout. T5 is the
 * aggressive, no-inter-probe-delay profile: for an operator's own authorized
 * lab there is effectively no rate throttle. Slower templates are gentler on
 * fragile targets. Scope is still enforced at every template.
 */
enum class Timing(
    val label: String,
    val concurrency: Int,
    val connectTimeoutMs: Int,
    val perProbeDelayMs: Long,
) {
    T0("T0 paranoid", 1, 4000, 800),
    T1("T1 sneaky", 1, 3000, 250),
    T2("T2 polite", 8, 2500, 50),
    T3("T3 normal", 48, 1500, 0),
    T4("T4 aggressive", 128, 900, 0),
    T5("T5 insane", 300, 600, 0);
}

/**
 * Parses an nmap-like port specification into an explicit, de-duplicated,
 * sorted list. Accepts: "80", "1-1024", "22,80,443", "80-90,443,8000-8100",
 * "-" (1-65535), "top100"/"top1000" (most common ports), or a named profile
 * ("common", "web"). Invalid tokens are ignored; an empty result falls back to
 * the COMMON profile so the UI never issues an empty scan.
 */
object PortSpec {
    fun parse(spec: String): Pair<List<Int>, String> {
        val s = spec.trim().lowercase()
        when {
            s.isEmpty() || s == "common" -> return ScanProfile.COMMON.ports to "common"
            s == "web" -> return ScanProfile.WEB.ports to "web"
            s == "-" || s == "all" -> return (1..65535).toList() to "all (1-65535)"
            s == "top100" -> return TOP_100 to "top-100"
            s == "top1000" -> return TOP_1000 to "top-1000"
            s == "1-1024" || s == "wellknown" -> return (1..1024).toList() to "1-1024"
        }
        val out = sortedSetOf<Int>()
        for (token in s.split(',')) {
            val t = token.trim()
            if (t.isEmpty()) continue
            if ('-' in t) {
                val (a, b) = t.split('-', limit = 2)
                val lo = a.trim().toIntOrNull() ?: continue
                val hi = b.trim().toIntOrNull() ?: continue
                for (p in lo.coerceAtLeast(1)..hi.coerceAtMost(65535)) out.add(p)
            } else t.toIntOrNull()?.takeIf { it in 1..65535 }?.let { out.add(it) }
        }
        if (out.isEmpty()) return ScanProfile.COMMON.ports to "common"
        return out.toList() to spec.trim()
    }

    /** The 100 most commonly open TCP ports (nmap top-ports order, abridged). */
    val TOP_100 = listOf(
        7,20,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,
        179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,
        873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,
        2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,
        5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,
        8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,
        49155,49156,49157,
    )

    /** Compact representation of nmap's top-1000: the well-known range plus a
     *  curated set of common high ports. Kept explicit for reproducibility. */
    val TOP_1000: List<Int> = ((1..1024) + TOP_100 + listOf(
        1433,1521,1723,2082,2083,2086,2087,2095,2096,2222,3000,3306,3389,4443,
        4444,5000,5432,5555,5900,5984,6379,7001,7002,8000,8008,8080,8081,8088,
        8090,8443,8444,8888,9000,9042,9090,9200,9300,9418,9999,10000,11211,
        15672,27017,27018,28017,50000,
    )).toSortedSet().toList()
}

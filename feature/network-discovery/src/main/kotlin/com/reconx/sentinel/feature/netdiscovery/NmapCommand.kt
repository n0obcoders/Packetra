package com.reconx.sentinel.feature.netdiscovery

/**
 * Parses a documented subset of nmap-style command text into a validated
 * [ScanConfig] + target. The text is NEVER passed to a shell — it is tokenized
 * and mapped to the on-device scanner's capabilities. Unsupported options return
 * an explicit error instead of being silently ignored (spec §9).
 *
 * Supported: -sT -sU -sn -Pn -p <spec> -F --top-ports N -T0..-T5 -sV -n
 * Target: the first bare (non-flag) token. "nmap" as the leading token is ignored.
 */
object NmapCommand {
    data class Result(val config: ScanConfig?, val target: String?, val errors: List<String>)

    private val SUPPORTED_HELP = "supported: -sT -sU -sn -Pn -p <ports> -F --top-ports N -T0..5 -sV -n <target>"

    fun parse(line: String): Result {
        val toks = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            .filterIndexed { i, t -> !(i == 0 && t.equals("nmap", true)) }
        if (toks.isEmpty()) return Result(null, null, listOf("empty command. $SUPPORTED_HELP"))

        var scanType = ScanType.TCP_CONNECT
        var timing = Timing.T3
        var ports: List<Int>? = null
        var portLabel = "common"
        var serviceDetection = false
        var hostDiscovery = true
        var target: String? = null
        val errors = mutableListOf<String>()

        var i = 0
        while (i < toks.size) {
            val t = toks[i]
            when {
                t == "-sT" -> scanType = ScanType.TCP_CONNECT
                t == "-sU" -> scanType = ScanType.UDP
                t == "-sn" -> scanType = ScanType.PING_SWEEP
                t == "-Pn" -> hostDiscovery = false
                t == "-sV" -> serviceDetection = true
                t == "-n" -> { /* no-DNS: accepted, we resolve once anyway */ }
                t == "-F" -> { ports = PortSpec.TOP_100; portLabel = "top-100 (-F)" }
                t == "-p" -> {
                    val spec = toks.getOrNull(++i)
                    if (spec == null) errors += "-p requires a port spec"
                    else { val (p, l) = PortSpec.parse(spec); ports = p; portLabel = l }
                }
                t.startsWith("-p") -> { val (p, l) = PortSpec.parse(t.substring(2)); ports = p; portLabel = l }
                t == "--top-ports" -> {
                    val n = toks.getOrNull(++i)?.toIntOrNull()
                    if (n == null) errors += "--top-ports requires a number"
                    else { ports = PortSpec.TOP_1000.take(n); portLabel = "top-$n" }
                }
                t.matches(Regex("-T[0-5]")) -> timing = Timing.entries[t[2].digitToInt()]
                t.startsWith("-") -> errors += "unsupported option '$t'. $SUPPORTED_HELP"
                else -> if (target == null) target = t else errors += "unexpected token '$t'"
            }
            i++
        }
        if (scanType != ScanType.PING_SWEEP && target == null) errors += "no target host specified"
        if (errors.isNotEmpty()) return Result(null, target, errors)

        val finalPorts = ports ?: if (scanType == ScanType.UDP) UDP_COMMON else ScanProfile.COMMON.ports
        return Result(ScanConfig(timing, finalPorts, serviceDetection,
            if (ports == null && scanType == ScanType.UDP) "udp-common" else portLabel,
            scanType, hostDiscovery), target, emptyList())
    }

    /** Common UDP service ports for the default -sU set. */
    val UDP_COMMON = listOf(53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353)
}

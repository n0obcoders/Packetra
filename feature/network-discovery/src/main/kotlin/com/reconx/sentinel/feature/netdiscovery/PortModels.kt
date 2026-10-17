package com.reconx.sentinel.feature.netdiscovery

/** Observed state of a TCP port. "FILTERED" = no response within timeout (we
 *  cannot distinguish a drop from a slow host, so we report it honestly). */
enum class PortState { OPEN, CLOSED, FILTERED }

data class PortResult(
    val host: String,
    val port: Int,
    val state: PortState,
    val latencyMs: Long?,
    val serviceGuess: String?,   // from the IANA well-known map (a label, not a probe)
    val product: String? = null, // from service/version detection (banner), if any
    val banner: String? = null,  // sanitized first-line banner, if any
)

data class HostScanResult(
    val host: String,
    val resolvedIp: String?,
    val ports: List<PortResult>,
    val reachable: Boolean,
    val error: String? = null,
) {
    val openPorts get() = ports.filter { it.state == PortState.OPEN }
}

/** Streaming events emitted during a scan so the UI shows live progress and
 *  never floods the screen with one error line per closed/filtered port. */
sealed interface ScanEvent {
    data class Resolved(val host: String, val ip: String, val totalPorts: Int) : ScanEvent
    data class Host(val up: Boolean, val method: String) : ScanEvent
    data class Open(val result: PortResult) : ScanEvent
    data class Progress(val scanned: Int, val total: Int, val open: Int) : ScanEvent
    data class Done(val scanned: Int, val open: Int, val closed: Int, val filtered: Int, val elapsedMs: Long) : ScanEvent
    data class Failed(val reason: String) : ScanEvent
}

/** Named scan profiles. Port sets are conservative and explicit. */
enum class ScanProfile(val ports: List<Int>, val label: String) {
    COMMON(listOf(21,22,23,25,53,80,110,143,443,445,587,993,995,3306,3389,5432,6379,8080,8443), "Common services"),
    WEB(listOf(80,443,8080,8443,8000,8888), "Web services"),
    TOP_FULL((1..1024).toList(), "Well-known TCP ports (1-1024)"),
}

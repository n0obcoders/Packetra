package com.reconx.sentinel.feature.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.reconx.sentinel.core.common.DefaultDispatchers
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Non-root local capture via Android's VpnService. Establishes an IPv4 TUN,
 * reads the device's OWN outbound packets, forwards TCP/UDP through protected
 * sockets so the device stays online, and feeds the capture engine (flow
 * tracking, DNS mapping, PCAP export).
 *
 * HONEST CAPABILITY STATEMENT (also in SECURITY.md / the Packet Analyzer screen):
 *  - Captures the DEVICE'S OWN traffic only — not other hosts', not raw Wi-Fi.
 *  - HTTPS/QUIC payloads stay ENCRYPTED; we read headers/metadata, never inject
 *    a CA or decrypt TLS.
 *  - Only IPv4 is routed through the capture; IPv6 is left to the OS so it is
 *    not black-holed (and therefore not captured).
 *  - The userspace TCP forwarder handles the common path; validate throughput on
 *    your device for heavy flows.
 */
class SentinelVpnService : VpnService() {
    private var iface: ParcelFileDescriptor? = null
    private var scope: CoroutineScope? = null
    private var engine: CaptureEngine? = null
    private var pcapServer: PcapOverIpServer? = null
    private val asnLookup = AsnLookup()
    private var startedAt: Long = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { teardown(); return START_NOT_STICKY }
        startForeground(NOTIF_ID, buildNotification())
        startCapture()
        return START_STICKY
    }

    private fun startCapture() {
        if (iface != null) return
        val builder = Builder()
            .setSession("Packetra capture")
            .addAddress(TUN_ADDRESS, 32)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)
            .setMtu(MTU)
        runCatching { builder.addDisallowedApplication(packageName) } // don't capture ourselves
        val fd = runCatching { builder.establish() }.getOrNull() ?: run { teardown(); return }
        iface = fd
        startedAt = System.currentTimeMillis()

        // Default to pcapng (modern Wireshark format, preserves per-packet
        // metadata for deep inspection); classic .pcap remains available.
        val fileSink: PacketSink? = runCatching {
            val dir = File(filesDir, "captures").apply { mkdirs() }
            val f = File(dir, "capture-${startedAt}.pcapng")
            CaptureController.lastPcapPath = f.absolutePath
            PcapngWriter(f)
        }.getOrNull()

        // Optional PCAP-over-IP server so a desktop Wireshark can read live.
        pcapServer = if (CaptureController.pcapOverIp.value)
            runCatching { PcapOverIpServer(CaptureController.pcapOverIpPort).also { it.start() } }.getOrNull()
        else null

        val sinks = listOfNotNull(fileSink, pcapServer)
        val pcap: PacketSink? = if (sinks.isEmpty()) null else CompositeSink(sinks)

        val tun = TunWriter(FileOutputStream(fd.fileDescriptor))
        val attributor = runCatching {
            AppAttributor(applicationContext, java.net.InetAddress.getByName(TUN_ADDRESS))
        }.getOrNull()
        val eng = CaptureEngine(
            tun = tun,
            socketProtect = { s -> protect(s) },
            datagramProtect = { s -> protect(s) },
            pcap = pcap,
            onDns = { CaptureController.addDns(it) },
            appResolver = attributor,
            asnLookup = { ip -> asnLookup.lookup(ip) },
            firewall = { CaptureController.firewallRules() },
            blocklist = { CaptureController.blocklist() },
            proxy = { CaptureController.proxyConfig() },
        )
        engine = eng

        val job = Job()
        val s = CoroutineScope(DefaultDispatchers.io + job).also { scope = it }
        CaptureController.setRunning(true)
        CaptureController.clear()
        s.launch { readLoop(fd, eng) }
        s.launch { publishLoop(eng, pcap) }
    }

    private suspend fun readLoop(fd: ParcelFileDescriptor, eng: CaptureEngine) {
        val input = FileInputStream(fd.fileDescriptor)
        val buffer = ByteArray(MTU)
        val local = scope ?: return
        while (local.isActive) {
            val n = runCatching { input.read(buffer) }.getOrDefault(-1)
            if (n <= 0) { if (n < 0) break else continue }
            runCatching { eng.onPacket(buffer, n) }
        }
    }

    private suspend fun publishLoop(eng: CaptureEngine, pcap: PacketSink?) {
        val local = scope ?: return
        var lastRev = -1L
        while (local.isActive) {
            // Rebuilding and re-publishing the flow/app lists is the expensive part,
            // so do it only when a packet actually changed something. Between bursts
            // this skips the sort/aggregate/recompose entirely — the UI stays idle
            // instead of churning every cycle. The view is capped so even a capture
            // with thousands of live flows lays out a bounded list.
            val revNow = eng.tracker.revision()
            if (revNow != lastRev) {
                lastRev = revNow
                CaptureController.publishFlows(eng.tracker.snapshot(MAX_FLOWS_IN_VIEW))
                CaptureController.publishAppUsage(eng.tracker.appUsage(MAX_APPS_IN_VIEW))
            }
            CaptureController.publishStats(
                CaptureStats(true, eng.tracker.size(), eng.tracker.packets, eng.tracker.bytes,
                    startedAt, pcap?.packets ?: 0,
                    blocked = eng.tracker.blockedCount,
                    pcapOverIpClients = pcapServer?.clients ?: 0)
            )
            delay(1000)
        }
    }

    private fun teardown() {
        CaptureController.setRunning(false)
        engine?.shutdown(); engine = null
        runCatching { pcapServer?.close() }; pcapServer = null
        scope?.cancel(); scope = null
        runCatching { iface?.close() }; iface = null
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        stopSelf()
    }

    override fun onDestroy() { teardown(); super.onDestroy() }
    override fun onRevoke() { teardown(); super.onRevoke() }

    /**
     * Keep capturing when the user swipes the app out of recents. A capture is a
     * long-running, user-started foreground service (like a music or call app), so
     * removing the task must NOT stop it — only the in-app Stop button or revoking
     * the VPN does. Combined with START_STICKY the system also restarts it if it is
     * ever killed for memory while still wanted.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        // Intentionally do not stop; the foreground service keeps running.
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "Traffic capture", NotificationManager.IMPORTANCE_LOW)
            )
        }
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("Packetra capture active")
            .setContentText("Capturing this device's own traffic for authorized analysis")
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "com.reconx.sentinel.capture.STOP"
        private const val CHANNEL = "sentinel_capture"
        private const val NOTIF_ID = 4201
        private const val MTU = 16384
        private const val TUN_ADDRESS = "10.111.222.1"
        // Upper bound on how many flows/apps the UI is handed per refresh. The
        // capture still tracks every flow and the PCAP records every packet; this
        // only bounds what the on-screen list has to render.
        private const val MAX_FLOWS_IN_VIEW = 500
        private const val MAX_APPS_IN_VIEW = 100
    }
}

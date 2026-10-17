package com.reconx.sentinel.feature.netdiscovery

import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * nmap -sV style service/version detection, bounded and non-destructive. For an
 * already-OPEN port it opens one short-lived connection and either reads a
 * service's greeting banner (SSH/FTP/SMTP/etc. announce themselves) or sends a
 * single benign HTTP request on web ports and reads the Server header. It never
 * sends more than one small probe, never writes application state, and caps the
 * bytes it reads. Returns a (product, banner) pair; both may be null.
 */
object ServiceDetector {
    private const val MAX_READ = 4096

    data class Detected(val product: String?, val banner: String?)

    fun detect(ip: String, port: Int, service: String?, connectTimeoutMs: Int): Detected {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, port), connectTimeoutMs)
                s.soTimeout = (connectTimeoutMs + 400).coerceAtMost(2500)
                val webLike = service == "http" || service == "https" || service == "http-alt" ||
                    port in intArrayOf(80, 443, 8080, 8443, 8000, 8888, 8008, 8081)
                if (webLike) probeHttp(s, ip) else grabBanner(s.getInputStream())
            }
        } catch (_: Throwable) {
            Detected(null, null)
        }
    }

    private fun probeHttp(s: Socket, host: String): Detected {
        return try {
            s.getOutputStream().write(
                ("HEAD / HTTP/1.0\r\nHost: $host\r\nUser-Agent: Packetra/1.0 (authorized)\r\n" +
                    "Accept: */*\r\nConnection: close\r\n\r\n").toByteArray()
            )
            s.getOutputStream().flush()
            val text = readText(s.getInputStream())
            val server = Regex("(?im)^server:\\s*(.+)$").find(text)?.groupValues?.get(1)?.trim()
            val status = text.lineSequence().firstOrNull()?.trim()
            Detected(server, status?.take(120))
        } catch (_: Throwable) { Detected(null, null) }
    }

    private fun grabBanner(input: InputStream): Detected {
        val text = readText(input)
        if (text.isBlank()) return Detected(null, null)
        val line = text.lineSequence().firstOrNull { it.isNotBlank() }?.trim()?.take(160)
        return Detected(line, line)
    }

    private fun readText(input: InputStream): String {
        val buf = ByteArray(MAX_READ)
        var total = 0
        try {
            while (total < MAX_READ) {
                val n = input.read(buf, total, MAX_READ - total)
                if (n <= 0) break
                total += n
                if (total >= 64 && buf.copyOf(total).decodeToString().contains("\r\n\r\n")) break
            }
        } catch (_: Throwable) { /* soTimeout or close: use what we have */ }
        return sanitize(buf.copyOf(total).decodeToString())
    }

    /** Keep printable characters + newlines; collapse control bytes so a binary
     *  service can't inject escape sequences into the UI. */
    private fun sanitize(s: String): String =
        s.map { if (it == '\n' || it == '\r' || it.code in 32..126) it else ' ' }.joinToString("")
}

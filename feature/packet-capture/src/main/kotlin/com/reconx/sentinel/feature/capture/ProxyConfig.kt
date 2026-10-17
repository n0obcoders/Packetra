package com.reconx.sentinel.feature.capture

import java.io.InputStream
import java.io.OutputStream

/**
 * Optional UPSTREAM proxy for captured TCP flows. When enabled, the userspace
 * TCP forwarder opens its protected socket to the proxy and asks the proxy to
 * reach the real destination (SOCKS5 CONNECT or HTTP CONNECT), instead of
 * connecting directly. This lets a user route their captured traffic through
 * their own VPN/proxy service while still capturing/analysing it locally.
 *
 * This is pure routing — it does NOT decrypt anything. HTTPS/TLS/QUIC payloads
 * remain end-to-end encrypted through the proxy exactly as they are directly.
 * UDP is still sent directly (SOCKS UDP-associate is out of scope), so DNS/QUIC
 * keep working; only TCP is tunnelled.
 */
data class ProxyConfig(
    val type: Type = Type.NONE,
    val host: String = "",
    val port: Int = 0,
    val username: String? = null,
    val password: String? = null,
) {
    enum class Type { NONE, SOCKS5, HTTP }

    val enabled: Boolean get() = type != Type.NONE && host.isNotBlank() && port in 1..65535
    val hasAuth: Boolean get() = !username.isNullOrEmpty()

    /** Human validation message, or null when the config is usable / disabled. */
    fun validate(): String? = when {
        type == Type.NONE -> null
        host.isBlank() -> "Proxy host is required."
        port !in 1..65535 -> "Proxy port must be 1–65535."
        else -> null
    }
}

/**
 * Pure byte-level builders/parsers for the two CONNECT handshakes, plus a small
 * driver that runs one over a socket's streams. Keeping the wire format pure
 * makes it unit-testable without a live proxy.
 */
object ProxyHandshake {

    // ---- SOCKS5 (RFC 1928 / 1929) ----

    fun socks5Greeting(hasAuth: Boolean): ByteArray =
        if (hasAuth) byteArrayOf(0x05, 0x02, 0x00, 0x02) // no-auth + user/pass
        else byteArrayOf(0x05, 0x01, 0x00)               // no-auth only

    fun socks5UserPass(user: String, pass: String): ByteArray {
        val u = user.toByteArray(Charsets.UTF_8); val p = pass.toByteArray(Charsets.UTF_8)
        val out = ByteArray(3 + u.size + p.size)
        out[0] = 0x01; out[1] = u.size.toByte()
        System.arraycopy(u, 0, out, 2, u.size)
        out[2 + u.size] = p.size.toByte()
        System.arraycopy(p, 0, out, 3 + u.size, p.size)
        return out
    }

    /** CONNECT request to an IPv4 destination (ATYP=0x01). */
    fun socks5ConnectV4(ip: ByteArray, port: Int): ByteArray {
        require(ip.size == 4) { "IPv4 address required" }
        return byteArrayOf(0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3],
            ((port ushr 8) and 0xFF).toByte(), (port and 0xFF).toByte())
    }

    // ---- HTTP CONNECT (RFC 7231 §4.3.6) ----

    fun httpConnect(hostPort: String, user: String?, pass: String?): ByteArray {
        val sb = StringBuilder()
        sb.append("CONNECT ").append(hostPort).append(" HTTP/1.1\r\n")
        sb.append("Host: ").append(hostPort).append("\r\n")
        if (!user.isNullOrEmpty()) {
            val token = java.util.Base64.getEncoder()
                .encodeToString("$user:${pass ?: ""}".toByteArray(Charsets.UTF_8))
            sb.append("Proxy-Authorization: Basic ").append(token).append("\r\n")
        }
        sb.append("Proxy-Connection: keep-alive\r\n\r\n")
        return sb.toString().toByteArray(Charsets.ISO_8859_1)
    }

    /** True if an HTTP CONNECT status line indicates success (2xx). */
    fun httpConnectOk(statusLine: String): Boolean {
        val parts = statusLine.trim().split(' ')
        val code = parts.getOrNull(1)?.toIntOrNull() ?: return false
        return code in 200..299
    }

    /**
     * Perform the configured handshake so [out]/[inp] become a tunnel to
     * (ipv4,port). Returns true on success. Throws nothing — returns false on any
     * protocol/IO error so the forwarder can fall back / reset the flow.
     */
    fun connect(cfg: ProxyConfig, ipv4: ByteArray, port: Int, out: OutputStream, inp: InputStream): Boolean =
        runCatching {
            when (cfg.type) {
                ProxyConfig.Type.SOCKS5 -> socks5(cfg, ipv4, port, out, inp)
                ProxyConfig.Type.HTTP -> http(cfg, ipv4, port, out, inp)
                ProxyConfig.Type.NONE -> true
            }
        }.getOrDefault(false)

    private fun socks5(cfg: ProxyConfig, ip: ByteArray, port: Int, out: OutputStream, inp: InputStream): Boolean {
        out.write(socks5Greeting(cfg.hasAuth)); out.flush()
        val method = ByteArray(2)
        if (!readFully(inp, method)) return false
        if (method[0].toInt() != 0x05) return false
        when (method[1].toInt() and 0xFF) {
            0x00 -> {} // no auth
            0x02 -> {
                out.write(socks5UserPass(cfg.username ?: "", cfg.password ?: "")); out.flush()
                val a = ByteArray(2)
                if (!readFully(inp, a) || a[1].toInt() != 0x00) return false
            }
            else -> return false // unsupported/ no acceptable method
        }
        out.write(socks5ConnectV4(ip, port)); out.flush()
        // Reply: VER REP RSV ATYP + BND.ADDR + BND.PORT
        val head = ByteArray(4)
        if (!readFully(inp, head)) return false
        if (head[0].toInt() != 0x05 || head[1].toInt() != 0x00) return false
        val addrLen = when (head[3].toInt() and 0xFF) {
            0x01 -> 4; 0x04 -> 16
            0x03 -> (inp.read().also { if (it < 0) return false }) // domain: 1 len byte then n
            else -> return false
        }
        val rest = ByteArray(addrLen + 2) // address + 2-byte port
        return readFully(inp, rest)
    }

    private fun http(cfg: ProxyConfig, ip: ByteArray, port: Int, out: OutputStream, inp: InputStream): Boolean {
        val hostPort = "${ip.joinToString(".") { (it.toInt() and 0xFF).toString() }}:$port"
        out.write(httpConnect(hostPort, cfg.username, cfg.password)); out.flush()
        val line = readLine(inp) ?: return false
        if (!httpConnectOk(line)) return false
        // drain remaining header lines up to the blank line
        while (true) { val l = readLine(inp) ?: return false; if (l.isEmpty()) break }
        return true
    }

    private fun readFully(inp: InputStream, b: ByteArray): Boolean {
        var read = 0
        while (read < b.size) {
            val n = inp.read(b, read, b.size - read)
            if (n < 0) return false
            read += n
        }
        return true
    }

    private fun readLine(inp: InputStream): String? {
        val sb = StringBuilder()
        var prev = -1
        while (true) {
            val c = inp.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (prev == '\r'.code && c == '\n'.code) { sb.setLength(sb.length - 1); return sb.toString() }
            sb.append(c.toChar()); prev = c
            if (sb.length > 8192) return sb.toString()
        }
    }
}

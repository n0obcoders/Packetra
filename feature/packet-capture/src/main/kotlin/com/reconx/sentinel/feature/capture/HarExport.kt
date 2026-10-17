package com.reconx.sentinel.feature.capture

/**
 * Builds a HAR 1.2 archive from the CLEARTEXT HTTP requests observed during a
 * capture. Honest scope: HTTPS/TLS traffic is encrypted and never decrypted, so
 * only plaintext HTTP/1.x requests (method, URL, host) appear here — there are no
 * request/response bodies, because this is a passive userspace capture, not a
 * man-in-the-middle proxy. A flow qualifies when a cleartext HTTP request line
 * was parsed from it.
 */
object HarExport {
    /** Returns a HAR JSON string, or null if no plaintext HTTP was observed. */
    fun build(flows: List<ConnectionFlow>): String? {
        val http = flows.filter { it.httpMethod != null && (it.httpHost != null || it.host != null) }
        if (http.isEmpty()) return null
        val entries = http.joinToString(",\n") { f ->
            val host = f.httpHost ?: f.host ?: f.destIp
            val path = f.httpPath ?: "/"
            val url = "http://$host$path"
            val started = isoTime(f.firstSeenEpochMs)
            """    {
      "startedDateTime": "${esc(started)}",
      "time": 0,
      "request": {
        "method": "${esc(f.httpMethod ?: "GET")}",
        "url": "${esc(url)}",
        "httpVersion": "HTTP/1.1",
        "headers": [ { "name": "Host", "value": "${esc(host)}" } ],
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": ${f.bytesOut}
      },
      "response": {
        "status": 0,
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "headers": [],
        "cookies": [],
        "content": { "size": ${f.bytesIn}, "mimeType": "" },
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": ${f.bytesIn}
      },
      "cache": {},
      "timings": { "send": 0, "wait": 0, "receive": 0 },
      "serverIPAddress": "${esc(f.destIp)}",
      "_appLabel": "${esc(f.appLabel ?: "")}",
      "_note": "metadata only — passive capture, no body or response captured"
    }"""
        }
        return """{
  "log": {
    "version": "1.2",
    "creator": { "name": "Packetra", "version": "1.0" },
    "comment": "Cleartext HTTP requests observed during a passive, non-root VpnService capture of this device's own traffic. HTTPS/TLS is encrypted and is NOT decrypted or included.",
    "entries": [
$entries
    ]
  }
}"""
    }

    private fun esc(s: String): String = buildString {
        for (c in s) when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c < ' ') append(' ') else append(c)
        }
    }

    private fun isoTime(epochMs: Long): String {
        // Avoid platform date APIs in this pure module; emit epoch-millis marker.
        return java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
            .format(java.util.Date(epochMs))
    }
}

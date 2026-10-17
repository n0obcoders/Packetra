package com.reconx.sentinel.feature.capture

/**
 * Malware / tracker detection by matching connection hostnames against one or
 * more third-party blocklists (hosts-file or domain-list format). Passive: it
 * only flags connections the device is already making. Lists are loaded by the
 * operator (e.g. a downloaded hosts file) so attribution of "malicious" is
 * transparent and updatable, never a hidden hardcoded verdict.
 */
class Blocklist(domains: Collection<String> = emptyList()) {
    private val set = HashSet<String>()
    init { domains.forEach { add(it) } }

    /** Accepts hosts-file lines ("0.0.0.0 bad.example") or bare domains; ignores comments. */
    fun add(line: String) {
        val t = line.trim()
        if (t.isEmpty() || t.startsWith("#")) return
        val host = t.split(Regex("\\s+")).lastOrNull()?.lowercase() ?: return
        if (host.contains('.')) set.add(host)
    }

    fun loadLines(lines: Sequence<String>): Int {
        val before = set.size
        lines.forEach { add(it) }
        return set.size - before
    }

    fun size() = set.size

    /** True if the host is on a blocklist (exact or parent-domain match). */
    fun isListed(host: String?): Boolean {
        if (host == null) return false
        val h = host.lowercase()
        if (h in set) return true
        var i = h.indexOf('.')
        while (i >= 0 && i < h.length - 1) {
            if (h.substring(i + 1) in set) return true
            i = h.indexOf('.', i + 1)
        }
        return false
    }
}

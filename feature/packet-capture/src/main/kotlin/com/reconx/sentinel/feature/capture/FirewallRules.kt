package com.reconx.sentinel.feature.capture

/**
 * On-device firewall rules for the capture VPN. Because every packet already
 * passes through our VpnService, we can DROP connections that match a rule
 * instead of forwarding them — blocking an app, a domain (suffix match) or an IP
 * for THIS device only. This is defensive self-control (like a per-app
 * firewall), not an attack on any remote host.
 *
 * Each app rule carries a protocol selector so the user can block an app over
 * TCP only, UDP only, or both — e.g. block an app's background QUIC/UDP while
 * leaving its TCP alone, or vice-versa. Multiple apps are blocked by listing
 * several rules. Immutable and pure so it is unit-testable; the engine consults
 * [decide] when a new connection is first seen.
 */
data class FirewallRules(
    val blockedApps: Set<AppRule> = emptySet(),
    val blockedDomains: Set<String> = emptySet(),  // suffix match, e.g. "ads.example.com"
    val blockedIps: Set<String> = emptySet(),      // exact IPv4
    val enabled: Boolean = false,
) {
    enum class Proto {
        TCP, UDP, BOTH;
        /** Does this selector apply to a connection of transport [p] ("TCP"/"UDP")? */
        fun matches(p: String?): Boolean = this == BOTH || p == null || name.equals(p, ignoreCase = true)
    }

    /** One app-block rule: a case-insensitive substring of the app label/package,
     *  plus which transport(s) it applies to. */
    data class AppRule(val match: String, val proto: Proto = Proto.BOTH)

    data class Decision(val blocked: Boolean, val reason: String? = null)

    /**
     * @param proto the connection's transport ("TCP"/"UDP"); when non-null, an app
     *   rule only matches if its protocol selector covers it. Domain/IP rules are
     *   transport-agnostic.
     */
    fun decide(appLabel: String?, host: String?, ip: String?, proto: String? = null): Decision {
        if (!enabled) return Decision(false)
        if (appLabel != null) {
            val hit = blockedApps.firstOrNull {
                it.match.isNotEmpty() && appLabel.contains(it.match, ignoreCase = true) && it.proto.matches(proto)
            }
            if (hit != null) return Decision(true, "app blocked (${hit.proto})")
        }
        if (host != null) {
            val h = host.lowercase()
            if (blockedDomains.any { d -> h == d || h.endsWith(".${d.trimStart('.')}") })
                return Decision(true, "domain blocked")
        }
        if (ip != null && ip in blockedIps) return Decision(true, "ip blocked")
        return Decision(false)
    }

    companion object {
        /**
         * Parse one text line into an [AppRule]. Accepts an optional protocol
         * suffix: "netflix", "netflix:udp", "com.app:tcp", "x:both". Unknown or
         * missing suffix falls back to [default].
         */
        fun parseAppRule(line: String, default: Proto): AppRule? {
            val t = line.trim()
            if (t.isEmpty()) return null
            val idx = t.lastIndexOf(':')
            if (idx > 0 && idx < t.length - 1) {
                val suffix = t.substring(idx + 1).trim().uppercase()
                val proto = when (suffix) { "TCP" -> Proto.TCP; "UDP" -> Proto.UDP; "BOTH" -> Proto.BOTH; else -> null }
                if (proto != null) return AppRule(t.substring(0, idx).trim().lowercase(), proto)
            }
            return AppRule(t.lowercase(), default)
        }
    }
}

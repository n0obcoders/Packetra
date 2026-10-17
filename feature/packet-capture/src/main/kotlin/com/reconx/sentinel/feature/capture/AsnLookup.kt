package com.reconx.sentinel.feature.capture

/**
 * Offline ASN / country lookup for IPv4 remote addresses. Ships with a seed
 * table covering the major hosting/CDN networks (so common destinations resolve
 * out of the box with no network call), and can be extended at runtime with a
 * fuller table (e.g. a GeoLite2/IP2ASN export) via [load]. Entirely offline —
 * no DNS, no third-party query — so it is private and battery-cheap.
 */
class AsnLookup(seed: List<Entry> = DEFAULT) {
    data class Entry(val cidr: String, val asn: String, val org: String, val country: String) {
        private val base: Long
        private val mask: Long
        init {
            val (ip, bits) = cidr.split('/')
            base = ipToLong(ip)
            val b = bits.toInt()
            mask = if (b == 0) 0L else (0xFFFFFFFFL shl (32 - b)) and 0xFFFFFFFFL
        }
        fun contains(ipLong: Long) = (ipLong and mask) == (base and mask)
    }

    data class Geo(val asn: String, val org: String, val country: String)

    private val entries = ArrayList(seed)

    fun load(extra: List<Entry>) { entries.addAll(extra) }

    fun lookup(ip: String): Geo? {
        val v = runCatching { ipToLong(ip) }.getOrNull() ?: return null
        // Longest-prefix-ish: first match in the ordered list wins.
        val e = entries.firstOrNull { it.contains(v) } ?: return null
        return Geo(e.asn, e.org, e.country)
    }

    companion object {
        fun ipToLong(ip: String): Long {
            val parts = ip.split('.')
            require(parts.size == 4) { "not IPv4: $ip" }
            var r = 0L
            for (p in parts) r = (r shl 8) or (p.toInt().toLong() and 0xFF)
            return r and 0xFFFFFFFFL
        }

        // A compact seed of well-known networks. Not exhaustive — a full DB can
        // be loaded via load(); unknown IPs simply return null (shown as "—").
        val DEFAULT = listOf(
            Entry("1.1.1.0/24", "AS13335", "Cloudflare", "US"),
            Entry("1.0.0.0/24", "AS13335", "Cloudflare", "US"),
            Entry("104.16.0.0/13", "AS13335", "Cloudflare", "US"),
            Entry("172.64.0.0/13", "AS13335", "Cloudflare", "US"),
            Entry("162.158.0.0/15", "AS13335", "Cloudflare", "US"),
            Entry("8.8.8.0/24", "AS15169", "Google", "US"),
            Entry("8.8.4.0/24", "AS15169", "Google", "US"),
            Entry("142.250.0.0/15", "AS15169", "Google", "US"),
            Entry("172.217.0.0/16", "AS15169", "Google", "US"),
            Entry("216.58.192.0/19", "AS15169", "Google", "US"),
            Entry("52.0.0.0/11", "AS16509", "Amazon AWS", "US"),
            Entry("54.144.0.0/12", "AS14618", "Amazon AWS", "US"),
            Entry("13.32.0.0/15", "AS16509", "Amazon CloudFront", "US"),
            Entry("151.101.0.0/16", "AS54113", "Fastly", "US"),
            Entry("23.32.0.0/11", "AS20940", "Akamai", "US"),
            Entry("104.64.0.0/10", "AS20940", "Akamai", "US"),
            Entry("20.0.0.0/8", "AS8075", "Microsoft Azure", "US"),
            Entry("40.64.0.0/10", "AS8075", "Microsoft Azure", "US"),
            Entry("157.240.0.0/16", "AS32934", "Meta/Facebook", "US"),
            Entry("31.13.24.0/21", "AS32934", "Meta/Facebook", "US"),
        )
    }
}

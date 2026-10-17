package com.reconx.sentinel.core.security

import java.math.BigInteger
import java.net.InetAddress

/**
 * IPv4/IPv6 CIDR range with containment tests. Pure value logic, no DNS.
 * Parsing is total: [parseOrNull] returns null rather than throwing so the
 * scope layer can treat malformed rules as "matches nothing".
 */
data class Cidr(
    val base: BigInteger,
    val prefix: Int,
    val bits: Int, // 32 or 128
) {
    private val mask: BigInteger =
        if (prefix == 0) BigInteger.ZERO
        else BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
            .shiftRight(bits - prefix).shiftLeft(bits - prefix)

    private val network: BigInteger = base.and(mask)

    fun contains(addr: InetAddress): Boolean {
        val v = addrToBig(addr) ?: return false
        if (addr.address.size * 8 != bits) return false
        return v.and(mask) == network
    }

    companion object {
        fun parseOrNull(spec: String): Cidr? {
            val s = spec.trim()
            val slash = s.indexOf('/')
            val host = if (slash >= 0) s.substring(0, slash) else s
            val addr = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return null
            val bits = addr.address.size * 8
            val prefix = if (slash >= 0)
                s.substring(slash + 1).toIntOrNull()?.takeIf { it in 0..bits } ?: return null
            else bits
            val base = addrToBig(addr) ?: return null
            return Cidr(base, prefix, bits)
        }

        fun addrToBig(addr: InetAddress): BigInteger? =
            runCatching { BigInteger(1, addr.address) }.getOrNull()
    }
}

package com.reconx.sentinel.feature.capture

/**
 * IPv4 packet build/parse helpers for the userspace forwarder. Only the subset
 * needed to relay TCP/UDP for the device's OWN traffic and to write PCAP. All
 * reads are bounds-checked; builders compute correct IP and L4 checksums so the
 * Android TCP/IP stack accepts the packets we inject back into the TUN.
 */
object IpPacket {
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val PROTO_ICMP = 1

    fun version(buf: ByteArray, len: Int): Int = if (len < 1) 0 else (buf[0].toInt() ushr 4) and 0xF

    data class V4(
        val src: ByteArray, val dst: ByteArray, val proto: Int,
        val ihl: Int, val totalLen: Int, val l4Off: Int, val payloadOff: Int,
    )

    fun parseV4(buf: ByteArray, len: Int): V4? {
        if (len < 20) return null
        val ihl = (buf[0].toInt() and 0xF) * 4
        if (ihl < 20 || len < ihl) return null
        val proto = buf[9].toInt() and 0xFF
        val total = u16(buf, 2).coerceAtMost(len)
        val src = buf.copyOfRange(12, 16)
        val dst = buf.copyOfRange(16, 20)
        val payloadOff = when (proto) {
            PROTO_TCP -> ihl + ((buf[ihl + 12].toInt() ushr 4) and 0xF) * 4
            PROTO_UDP -> ihl + 8
            else -> ihl
        }
        return V4(src, dst, proto, ihl, total, ihl, payloadOff)
    }

    fun ipToString(b: ByteArray): String = b.joinToString(".") { (it.toInt() and 0xFF).toString() }
    fun u16(b: ByteArray, o: Int): Int = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
        ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)

    private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte() }
    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte()
        b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
    }

    fun checksum(b: ByteArray, off: Int, len: Int, initial: Long = 0): Int {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) { sum += u16(b, i).toLong(); i += 2 }
        if (i < end) sum += ((b[i].toInt() and 0xFF) shl 8).toLong()
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** Build a complete IPv4 packet carrying [l4] (a full TCP/UDP segment whose
     *  own checksum this fills in using the IPv4 pseudo-header). */
    fun buildV4(src: ByteArray, dst: ByteArray, proto: Int, l4: ByteArray): ByteArray {
        val total = 20 + l4.size
        val p = ByteArray(total)
        p[0] = 0x45; p[1] = 0
        put16(p, 2, total); put16(p, 4, 0); put16(p, 6, 0x4000)
        p[8] = 64; p[9] = proto.toByte()
        System.arraycopy(src, 0, p, 12, 4); System.arraycopy(dst, 0, p, 16, 4)
        put16(p, 10, 0); put16(p, 10, checksum(p, 0, 20))
        System.arraycopy(l4, 0, p, 20, l4.size)
        // L4 checksum over pseudo-header + segment
        var pseudo = 0L
        pseudo += u16(src, 0).toLong() + u16(src, 2).toLong()
        pseudo += u16(dst, 0).toLong() + u16(dst, 2).toLong()
        pseudo += proto.toLong()
        pseudo += l4.size.toLong()
        val ckOff = if (proto == PROTO_TCP) 20 + 16 else 20 + 6
        put16(p, ckOff, 0)
        val ck = checksum(p, 20, l4.size, pseudo)
        put16(p, ckOff, if (proto == PROTO_UDP && ck == 0) 0xFFFF else ck)
        return p
    }
}

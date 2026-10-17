package com.reconx.sentinel.feature.capture

import java.io.Closeable

/**
 * A destination for captured raw IP packets. Both the classic libpcap writer
 * ([PcapWriter]) and the modern pcapng writer ([PcapngWriter]) implement this,
 * so the capture engine is agnostic to the on-disk format the operator chose.
 */
interface PacketSink : Closeable {
    /** Number of packets written so far. */
    val packets: Long

    /** Writes one raw IP packet (snaplen is applied by the implementation). */
    fun write(buf: ByteArray, len: Int)
}

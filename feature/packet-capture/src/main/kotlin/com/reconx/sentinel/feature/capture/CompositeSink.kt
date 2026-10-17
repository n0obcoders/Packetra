package com.reconx.sentinel.feature.capture

/** Fans one packet out to several sinks (e.g. the .pcapng file + PCAP-over-IP). */
class CompositeSink(private val sinks: List<PacketSink>) : PacketSink {
    override val packets: Long get() = sinks.firstOrNull()?.packets ?: 0
    override fun write(buf: ByteArray, len: Int) { for (s in sinks) runCatching { s.write(buf, len) } }
    override fun close() { sinks.forEach { runCatching { it.close() } } }
}

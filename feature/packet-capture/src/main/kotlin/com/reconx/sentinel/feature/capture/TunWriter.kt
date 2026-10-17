package com.reconx.sentinel.feature.capture

import java.io.FileOutputStream

/** Serializes writes of crafted reply packets back into the TUN fd. */
class TunWriter(private val out: FileOutputStream) {
    @Synchronized fun write(packet: ByteArray) { runCatching { out.write(packet); out.flush() } }
}

/** Abstraction over VpnService.protect so forwarders stay unit-testable. */
fun interface SocketProtector { fun protect(socket: java.net.Socket): Boolean }
fun interface DatagramProtector { fun protect(socket: java.net.DatagramSocket): Boolean }

package com.reconx.sentinel.feature.netdiscovery

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PortUnreachableException

/**
 * UDP service probe (nmap -sU, non-root subset). Sends one small, protocol-aware
 * and benign datagram and classifies the result honestly:
 *  - OPEN               a reply was received
 *  - CLOSED             an ICMP port-unreachable surfaced as PortUnreachableException
 *  - FILTERED           no reply within the timeout (nmap's "open|filtered"; we
 *                       cannot disambiguate without raw ICMP, so we say so)
 * Probes are read-only service queries (DNS/NTP/SNMP-get/NetBIOS) — nothing
 * state-changing.
 */
object UdpProbe {
    fun probe(ip: String, port: Int, timeoutMs: Int): PortState {
        return try {
            DatagramSocket().use { s ->
                s.soTimeout = timeoutMs
                s.connect(InetSocketAddress(InetAddress.getByName(ip), port))
                val payload = payloadFor(port)
                s.send(DatagramPacket(payload, payload.size))
                val resp = ByteArray(2048)
                s.receive(DatagramPacket(resp, resp.size)) // throws on timeout / unreachable
                PortState.OPEN
            }
        } catch (e: PortUnreachableException) {
            PortState.CLOSED
        } catch (e: java.net.SocketTimeoutException) {
            PortState.FILTERED
        } catch (e: Throwable) {
            PortState.FILTERED
        }
    }

    private fun payloadFor(port: Int): ByteArray = when (port) {
        53 -> byteArrayOf( // DNS standard query A for "."
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01)
        123 -> ByteArray(48).also { it[0] = 0x1B } // NTPv3 client request
        161 -> SNMP_GET_SYSDESCR                     // SNMP v1 get sysDescr, community "public"
        137 -> NETBIOS_NAME_QUERY
        else -> byteArrayOf(0x00)
    }

    // SNMPv1 GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr), community "public" — read-only.
    private val SNMP_GET_SYSDESCR = intArrayOf(
        0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa0,0x19,
        0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0b,0x30,
        0x09,0x06,0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00
    ).map { it.toByte() }.toByteArray()

    private val NETBIOS_NAME_QUERY = intArrayOf(
        0x80,0xf0,0x00,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x43,0x4b,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x00,0x00,0x21,0x00,0x01
    ).map { it.toByte() }.toByteArray()
}

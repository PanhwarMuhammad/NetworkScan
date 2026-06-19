package com.muhammad.networkscan.util

import java.nio.ByteBuffer

/**
 * Parses raw IPv4 packets read from the VPN TUN interface.
 * All offsets are in bytes from the start of the IP header.
 */
object PacketParser {

    // IPv4 field offsets
    private const val IP_VER_IHL = 0
    private const val IP_TOTAL_LEN = 2
    private const val IP_PROTOCOL = 9
    private const val IP_SRC = 12
    private const val IP_DST = 16
    private const val IP_HEADER_MIN = 20

    // TCP field offsets (from start of TCP header)
    private const val TCP_SRC_PORT = 0
    private const val TCP_DST_PORT = 2
    private const val TCP_DATA_OFFSET = 12
    private const val TCP_FLAGS = 13

    // TCP flag masks
    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10
    const val FLAG_URG = 0x20

    // UDP field offsets (from start of UDP header)
    private const val UDP_SRC_PORT = 0
    private const val UDP_DST_PORT = 2

    // Protocol numbers
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val PROTO_ICMP = 1

    data class ParsedPacket(
        val srcIp: String,
        val dstIp: String,
        val protocol: Int,
        val srcPort: Int,
        val dstPort: Int,
        val totalLength: Int,
        val ipHeaderLength: Int,
        val tcpFlags: Int = 0
    )

    /**
     * Returns null if the buffer doesn't contain a valid IPv4 packet.
     */
    fun parse(buffer: ByteArray, length: Int): ParsedPacket? {
        if (length < IP_HEADER_MIN) return null

        val bb = ByteBuffer.wrap(buffer, 0, length)

        // Check IPv4 version
        val verIhl = bb.get(IP_VER_IHL).toInt() and 0xFF
        val version = verIhl shr 4
        if (version != 4) return null  // Only handle IPv4

        val ihl = (verIhl and 0x0F) * 4  // IP header length in bytes
        if (ihl < IP_HEADER_MIN || ihl > length) return null

        val totalLen = bb.getShort(IP_TOTAL_LEN).toInt() and 0xFFFF
        if (totalLen > length) return null

        val protocol = bb.get(IP_PROTOCOL).toInt() and 0xFF

        val srcIp = formatIp(bb, IP_SRC)
        val dstIp = formatIp(bb, IP_DST)

        if (length < ihl) return null

        var srcPort = 0
        var dstPort = 0
        var tcpFlags = 0

        when (protocol) {
            PROTO_TCP -> {
                if (length < ihl + 14) return null
                srcPort = bb.getShort(ihl + TCP_SRC_PORT).toInt() and 0xFFFF
                dstPort = bb.getShort(ihl + TCP_DST_PORT).toInt() and 0xFFFF
                tcpFlags = bb.get(ihl + TCP_FLAGS).toInt() and 0xFF
            }
            PROTO_UDP -> {
                if (length < ihl + 4) return null
                srcPort = bb.getShort(ihl + UDP_SRC_PORT).toInt() and 0xFFFF
                dstPort = bb.getShort(ihl + UDP_DST_PORT).toInt() and 0xFFFF
            }
            PROTO_ICMP -> {
                // ICMP has no ports
            }
        }

        return ParsedPacket(
            srcIp = srcIp,
            dstIp = dstIp,
            protocol = protocol,
            srcPort = srcPort,
            dstPort = dstPort,
            totalLength = totalLen,
            ipHeaderLength = ihl,
            tcpFlags = tcpFlags
        )
    }

    private fun formatIp(bb: ByteBuffer, offset: Int): String {
        return "${bb.get(offset).toInt() and 0xFF}" +
               ".${bb.get(offset + 1).toInt() and 0xFF}" +
               ".${bb.get(offset + 2).toInt() and 0xFF}" +
               ".${bb.get(offset + 3).toInt() and 0xFF}"
    }

    fun protocolName(proto: Int): String = when (proto) {
        PROTO_TCP -> "TCP"
        PROTO_UDP -> "UDP"
        PROTO_ICMP -> "ICMP"
        else -> "OTHER($proto)"
    }
}

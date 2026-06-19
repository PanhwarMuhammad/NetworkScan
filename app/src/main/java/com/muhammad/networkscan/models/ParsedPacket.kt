package com.muhammad.networkscan.models


import java.nio.ByteBuffer
import java.nio.ByteOrder

// ─────────────────────────────────────────────────────────────────────────────
// PacketParser.kt
//
// Parses raw Layer-3 packets read from the VpnService TUN file descriptor.
// The VPN tunnel delivers raw IPv4 (and sometimes IPv6) datagrams.
//
// What we CAN see:
//   • IP header (src/dst addr, TTL, protocol, total length, ID, flags)
//   • TCP header (src/dst port, seq/ack, flags, window size, header length)
//   • UDP header (src/dst port, length)
//   • ICMP type/code
//   • TLS ClientHello SNI (first byte of TLS records, plaintext extension)
//
// What we CANNOT see (encrypted):
//   • HTTP/2 request bodies, headers after TLS handshake
//   • Application-layer payload after TLS is established
// ─────────────────────────────────────────────────────────────────────────────

/** Direction relative to the local device */
enum class Direction { FORWARD, BACKWARD }

data class ParsedPacket(
    val timestampUs: Long,          // capture time µs (System.nanoTime / 1000)
    val direction: Direction,


    // IP layer
    val ipVersion: Int,             // 4 or 6
    val protocol: Int,              // 6=TCP, 17=UDP, 1=ICMP
    val srcIp: String,
    val dstIp: String,
    val totalLength: Int,           // IP total-length field
    val ttl: Int,
    val ipHeaderLength: Int,        // bytes

    // Transport layer
    val srcPort: Int,               // 0 for ICMP
    val dstPort: Int,
    val tcpFlags: Int,              // bitmask; 0 for UDP/ICMP
    val tcpWindowSize: Int,
    val tcpHeaderLength: Int,
    val tcpSeq: Long,
    val tcpAck: Long,
    val payloadLength: Int,         // bytes of data after transport header

    // TLS (best-effort)
    val tlsSni: String,             // "" if not a TLS ClientHello

    // Derived
    val isEncrypted: Boolean        // port 443/8443/853/465/995/993
) {
    val PROTO_TCP = 6
    val PROTO_UDP = 17
    val PROTO_ICMP = 1

    val isTcp: Boolean get() = protocol == PROTO_TCP
    val isUdp: Boolean get() = protocol == PROTO_UDP
    val isIcmp: Boolean get() = protocol == PROTO_ICMP

    // TCP flag helpers
    val flagFin: Boolean get() = tcpFlags and 0x01 != 0
    val flagSyn: Boolean get() = tcpFlags and 0x02 != 0
    val flagRst: Boolean get() = tcpFlags and 0x04 != 0
    val flagPsh: Boolean get() = tcpFlags and 0x08 != 0
    val flagAck: Boolean get() = tcpFlags and 0x10 != 0
    val flagUrg: Boolean get() = tcpFlags and 0x20 != 0
    val flagEce: Boolean get() = tcpFlags and 0x40 != 0
    val flagCwe: Boolean get() = tcpFlags and 0x80 != 0
}

object PacketParser {

    private const val PROTO_TCP  = 6
    private const val PROTO_UDP  = 17
    private const val PROTO_ICMP = 1

    private val ENCRYPTED_PORTS = setOf(443, 8443, 853, 465, 995, 993, 8883)

    /**
     * Parse a raw packet from the VPN tunnel.
     * [rawBytes] – the exact bytes read from the ParcelFileDescriptor input stream.
     * Returns null if the packet is malformed or unsupported (e.g. IPv6 without enough bytes).
     */
    fun parse(rawBytes: ByteArray, length: Int, nowUs: Long): ParsedPacket? {
        if (length < 20) return null   // minimum IPv4 header

        val buf = ByteBuffer.wrap(rawBytes, 0, length).order(ByteOrder.BIG_ENDIAN)
        val firstByte = buf.get(0).toInt() and 0xFF
        val ipVersion = firstByte ushr 4

        return when (ipVersion) {
            4 -> parseIPv4(buf, length, nowUs)
            6 -> parseIPv6(buf, length, nowUs)   // limited support
            else -> null
        }
    }

    // ── IPv4 ─────────────────────────────────────────────────────────────────

    private fun parseIPv4(buf: ByteBuffer, length: Int, nowUs: Long): ParsedPacket? {
        val ihl      = (buf.get(0).toInt() and 0x0F) * 4   // IP header length bytes
        if (ihl < 20 || ihl > length) return null

        val totalLen = buf.getShort(2).toInt() and 0xFFFF
        val protocol = buf.get(9).toInt() and 0xFF
        val ttl      = buf.get(8).toInt() and 0xFF
        val srcIp    = formatIPv4(buf, 12)
        val dstIp    = formatIPv4(buf, 16)

        if (ihl >= length) {
            // no transport payload
            return buildPacket(nowUs, ipVersion=4, protocol=protocol,
                srcIp=srcIp, dstIp=dstIp, totalLength=totalLen,
                ttl=ttl, ipHeaderLength=ihl,
                transportBuf=null, transportOffset=ihl, remaining=0)
        }

        val transportBuf = ByteBuffer.wrap(buf.array(), ihl, length - ihl)
            .order(ByteOrder.BIG_ENDIAN)

        return buildPacket(nowUs, ipVersion=4, protocol=protocol,
            srcIp=srcIp, dstIp=dstIp, totalLength=totalLen,
            ttl=ttl, ipHeaderLength=ihl,
            transportBuf=transportBuf, transportOffset=ihl, remaining=length - ihl)
    }

    // ── IPv6 (minimal) ───────────────────────────────────────────────────────

    private fun parseIPv6(buf: ByteBuffer, length: Int, nowUs: Long): ParsedPacket? {
        if (length < 40) return null
        val nextHeader = buf.get(6).toInt() and 0xFF
        val srcIp = formatIPv6(buf, 8)
        val dstIp = formatIPv6(buf, 24)
        val payloadLen = buf.getShort(4).toInt() and 0xFFFF
        val transportBuf = if (length > 40)
            ByteBuffer.wrap(buf.array(), 40, length - 40).order(ByteOrder.BIG_ENDIAN)
        else null

        return buildPacket(nowUs, ipVersion=6, protocol=nextHeader,
            srcIp=srcIp, dstIp=dstIp, totalLength=40 + payloadLen,
            ttl=0, ipHeaderLength=40,
            transportBuf=transportBuf, transportOffset=40, remaining=length - 40)
    }

    // ── Transport dispatch ───────────────────────────────────────────────────

    private fun buildPacket(
        nowUs: Long, ipVersion: Int, protocol: Int,
        srcIp: String, dstIp: String, totalLength: Int, ttl: Int, ipHeaderLength: Int,
        transportBuf: ByteBuffer?, transportOffset: Int, remaining: Int
    ): ParsedPacket {

        var srcPort = 0; var dstPort = 0
        var tcpFlags = 0; var tcpWindow = 0; var tcpHeaderLen = 0
        var tcpSeq = 0L; var tcpAck = 0L
        var payloadLength = 0
        var sni = ""

        when (protocol) {
            PROTO_TCP -> if (transportBuf != null && remaining >= 20) {
                srcPort      = transportBuf.getShort(0).toInt() and 0xFFFF
                dstPort      = transportBuf.getShort(2).toInt() and 0xFFFF
                tcpSeq       = transportBuf.getInt(4).toLong() and 0xFFFFFFFFL
                tcpAck       = transportBuf.getInt(8).toLong() and 0xFFFFFFFFL
                val dataOff  = (transportBuf.get(12).toInt() and 0xF0) ushr 4
                tcpHeaderLen = dataOff * 4
                tcpFlags     = transportBuf.get(13).toInt() and 0xFF
                tcpWindow    = transportBuf.getShort(14).toInt() and 0xFFFF
                payloadLength = maxOf(0, remaining - tcpHeaderLen)

                // TLS SNI – only on SYN-less packets going to encrypted ports
                if (payloadLength > 5 && ENCRYPTED_PORTS.contains(dstPort)) {
                    sni = extractSni(transportBuf.array(),
                        transportOffset + tcpHeaderLen, payloadLength)
                }
            }
            PROTO_UDP -> if (transportBuf != null && remaining >= 8) {
                srcPort       = transportBuf.getShort(0).toInt() and 0xFFFF
                dstPort       = transportBuf.getShort(2).toInt() and 0xFFFF
                payloadLength = maxOf(0, (transportBuf.getShort(4).toInt() and 0xFFFF) - 8)
            }
            PROTO_ICMP -> { /* no ports */ }
        }

        val encrypted = ENCRYPTED_PORTS.contains(dstPort) || ENCRYPTED_PORTS.contains(srcPort)

        // Direction: if srcPort is a high ephemeral port and dstPort is well-known → FORWARD
        val direction = if (srcPort > 1023 && dstPort <= 1023) Direction.FORWARD
        else if (dstPort > 1023 && srcPort <= 1023) Direction.BACKWARD
        else Direction.FORWARD  // default

        return ParsedPacket(
            timestampUs     = nowUs,
            direction       = direction,
            ipVersion       = ipVersion,
            protocol        = protocol,
            srcIp           = srcIp,
            dstIp           = dstIp,
            totalLength     = totalLength,
            ttl             = ttl,
            ipHeaderLength  = ipHeaderLength,
            srcPort         = srcPort,
            dstPort         = dstPort,
            tcpFlags        = tcpFlags,
            tcpWindowSize   = tcpWindow,
            tcpHeaderLength = tcpHeaderLen,
            tcpSeq          = tcpSeq,
            tcpAck          = tcpAck,
            payloadLength   = payloadLength,
            tlsSni          = sni,
            isEncrypted     = encrypted
        )
    }

    // ── TLS SNI extraction ───────────────────────────────────────────────────

    /**
     * Try to read the SNI from a TLS ClientHello.
     * Format reference: RFC 5246 / RFC 6066
     * Returns "" if not a ClientHello or SNI is absent.
     */
    private fun extractSni(data: ByteArray, offset: Int, length: Int): String {
        // TLS record: ContentType(1) Version(2) Length(2) Handshake...
        if (length < 5) return ""
        if (data[offset].toInt() and 0xFF != 0x16) return "" // not Handshake
        val recordLen = ((data[offset+3].toInt() and 0xFF) shl 8) or
                (data[offset+4].toInt() and 0xFF)
        if (length < 5 + recordLen) return ""

        // Handshake: Type(1) Length(3) ClientHello body
        val hOffset = offset + 5
        if (data[hOffset].toInt() and 0xFF != 0x01) return "" // not ClientHello

        // Skip: type(1) + len(3) + version(2) + random(32) + sessionIdLen(1) → 39
        var pos = hOffset + 4 + 2 + 32
        if (pos >= offset + length) return ""
        val sessionIdLen = data[pos++].toInt() and 0xFF
        pos += sessionIdLen

        // cipher suites
        if (pos + 2 > offset + length) return ""
        val cipherSuiteLen = ((data[pos].toInt() and 0xFF) shl 8) or
                (data[pos+1].toInt() and 0xFF)
        pos += 2 + cipherSuiteLen

        // compression
        if (pos + 1 > offset + length) return ""
        val compLen = data[pos++].toInt() and 0xFF
        pos += compLen

        // extensions length
        if (pos + 2 > offset + length) return ""
        val extLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos+1].toInt() and 0xFF)
        pos += 2
        val extEnd = pos + extLen

        while (pos + 4 <= extEnd && extEnd <= offset + length) {
            val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos+1].toInt() and 0xFF)
            val extDataLen = ((data[pos+2].toInt() and 0xFF) shl 8) or (data[pos+3].toInt() and 0xFF)
            pos += 4
            if (extType == 0x0000) { // server_name
                // list length(2) type(1) name length(2) name
                if (pos + 5 <= extEnd) {
                    val nameLen = ((data[pos+3].toInt() and 0xFF) shl 8) or
                            (data[pos+4].toInt() and 0xFF)
                    val nameStart = pos + 5
                    if (nameStart + nameLen <= extEnd) {
                        return String(data, nameStart, nameLen, Charsets.US_ASCII)
                    }
                }
            }
            pos += extDataLen
        }
        return ""
    }

    // ── Formatting helpers ───────────────────────────────────────────────────

    private fun formatIPv4(buf: ByteBuffer, offset: Int): String =
        "${buf.get(offset).toInt() and 0xFF}." +
                "${buf.get(offset+1).toInt() and 0xFF}." +
                "${buf.get(offset+2).toInt() and 0xFF}." +
                "${buf.get(offset+3).toInt() and 0xFF}"

    private fun formatIPv6(buf: ByteBuffer, offset: Int): String {
        val sb = StringBuilder()
        for (i in 0 until 8) {
            if (i > 0) sb.append(':')
            val hi = buf.get(offset + i*2).toInt() and 0xFF
            val lo = buf.get(offset + i*2 + 1).toInt() and 0xFF
            sb.append("%02x%02x".format(hi, lo))
        }
        return sb.toString()
    }
}
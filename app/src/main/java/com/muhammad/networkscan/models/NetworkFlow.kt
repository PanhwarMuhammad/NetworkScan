package com.muhammad.networkscan.models

data class NetworkFlow(
    val flowId: String,
    val protocol: String,          // TCP, UDP, ICMP, OTHER
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val startTimeMs: Long,
    var lastSeenMs: Long,
    var fwdPackets: Long = 0,
    var fwdBytes: Long = 0,
    var bwdPackets: Long = 0,
    var bwdBytes: Long = 0,
    var totalPackets: Long = 0,
    var totalBytes: Long = 0,
    var minPacketLen: Int = Int.MAX_VALUE,
    var maxPacketLen: Int = 0,
    var tcpFlags: Int = 0,         // OR'd TCP flag bytes
    var finCount: Int = 0,
    var synCount: Int = 0,
    var rstCount: Int = 0,
    var pshCount: Int = 0,
    var ackCount: Int = 0,
    var urgCount: Int = 0
) {
    val durationMs: Long get() = lastSeenMs - startTimeMs

    val avgPacketLen: Double
        get() = if (totalPackets > 0) totalBytes.toDouble() / totalPackets else 0.0

    val bytesPerSecond: Double
        get() = if (durationMs > 0) totalBytes.toDouble() / (durationMs / 1000.0) else 0.0

    val packetsPerSecond: Double
        get() = if (durationMs > 0) totalPackets.toDouble() / (durationMs / 1000.0) else 0.0
}

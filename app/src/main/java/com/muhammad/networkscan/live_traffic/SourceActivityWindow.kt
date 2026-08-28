package com.muhammad.networkscan.live_traffic

import com.muhammad.networkscan.models.NetworkFlow


 // Tracks recent activity from a single source IP over a sliding time window.

class SourceActivityWindow(private val windowMs: Long = 10_000L) {

    private data class TimestampedTarget(
        val timestampMs: Long,
        val dstIp: String,
        val dstPort: Int,
        val synCount: Long,
        val totalPackets: Long
    )

    private val recentTargets = ArrayDeque<TimestampedTarget>()

    fun record(flow: NetworkFlow) {
        recentTargets.addLast(
            TimestampedTarget(
                timestampMs = flow.lastSeenMs,
                dstIp = flow.dstIp,
                dstPort = flow.dstPort,
                synCount = flow.synCount.toLong(),
                totalPackets = flow.totalPackets
            )
        )
        prune(flow.lastSeenMs)
    }

    private fun prune(nowMs: Long) {
        while (recentTargets.isNotEmpty() && nowMs - recentTargets.first().timestampMs > windowMs) {
            recentTargets.removeFirst()
        }
        while (recentTargets.size > 500) {
            recentTargets.removeFirst()
        }
    }

    fun distinctPortCount(nowMs: Long): Int {
        prune(nowMs)
        return recentTargets.map { it.dstPort }.distinct().size
    }

    fun distinctIpCount(nowMs: Long): Int {
        prune(nowMs)
        return recentTargets.map { it.dstIp }.distinct().size
    }

    fun totalSynCount(nowMs: Long): Long {
        prune(nowMs)
        return recentTargets.sumOf { it.synCount }
    }

    fun distinctSynTargetCount(nowMs: Long): Int {
        prune(nowMs)
        return recentTargets.filter { it.synCount > 0 }.map { it.dstIp to it.dstPort }.distinct().size
    }

    fun singlePacketFlowCount(nowMs: Long): Int {
        prune(nowMs)
        return recentTargets.count { it.totalPackets <= 1 }
    }

    fun repeatedTargetCount(nowMs: Long): Int {
        prune(nowMs)
        return recentTargets.groupingBy { it.dstIp to it.dstPort }.eachCount().values.count { it >= 3 }
    }
}
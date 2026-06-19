package com.muhammad.networkscan.classifier


import com.muhammad.networkscan.models.FlowRecord
import com.muhammad.networkscan.models.ParsedPacket
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

// ─────────────────────────────────────────────────────────────────────────────
// FlowTracker.kt
//
// Maintains a table of active flows, accumulates per-packet statistics, and
// emits a completed FlowRecord when:
//   • A TCP FIN or RST is seen (flow teardown)
//   • A flow has been idle for IDLE_TIMEOUT_US microseconds
//   • The active-flow table exceeds MAX_FLOWS (oldest evicted)
//
// All arithmetic uses Long/Double to avoid overflow on large flows.
// ─────────────────────────────────────────────────────────────────────────────

class FlowTracker(
    private val onFlowComplete: (FlowRecord) -> Unit,
    private val idleTimeoutUs: Long = 30_000_000L,   // 30 s
    private val maxFlows: Int = 512
) {

    // ── Flow key ─────────────────────────────────────────────────────────────

    private data class FlowKey(
        val proto: Int,
        val lowIp: String, val lowPort: Int,
        val highIp: String, val highPort: Int
    )

    private fun packetKey(p: ParsedPacket): FlowKey {
        // Make key direction-agnostic (canonicalize src/dst)
        val (aIp, aPort, bIp, bPort) =
            if (p.srcIp < p.dstIp || (p.srcIp == p.dstIp && p.srcPort <= p.dstPort))
                listOf(p.srcIp, p.srcPort, p.dstIp, p.dstPort)
            else
                listOf(p.dstIp, p.dstPort, p.srcIp, p.srcPort)
        return FlowKey(p.protocol, aIp.toString(), aPort as Int, bIp.toString(), bPort as Int)
    }

    // ── Mutable accumulator ───────────────────────────────────────────────────

    private inner class FlowAccumulator(first: ParsedPacket) {
        val key          = packetKey(first)
        val startUs      = first.timestampUs
        val protocol     = first.protocol
        val protocolName = when (first.protocol) { 6 -> "TCP"; 17 -> "UDP"; 1 -> "ICMP"; else -> "OTHER" }

        // The "forward" direction is whichever direction the first packet came from
        val fwdSrcIp   = first.srcIp
        val fwdDstIp   = first.dstIp
        val fwdSrcPort = first.srcPort
        val fwdDstPort = first.dstPort

        var lastSeenUs = first.timestampUs

        // packet lists (lengths in bytes)
        val fwdLengths  = mutableListOf<Double>()
        val bwdLengths  = mutableListOf<Double>()
        val allLengths  = mutableListOf<Double>()

        // IAT lists (µs)
        val allIats  = mutableListOf<Double>()
        val fwdIats  = mutableListOf<Double>()
        val bwdIats  = mutableListOf<Double>()
        var lastFwdTs = first.timestampUs
        var lastBwdTs = -1L
        var lastAllTs = first.timestampUs

        // TCP flags
        var finCount = 0; var synCount = 0; var rstCount = 0; var pshCount = 0
        var ackCount = 0; var urgCount = 0; var cweCount = 0; var eceCount = 0
        var fwdPsh = 0; var fwdUrg = 0
        var bwdPsh = 0; var bwdUrg = 0

        // header lengths
        var fwdHeaderBytes = 0L
        var bwdHeaderBytes = 0L

        // window sizes (first SYN / SYN-ACK)
        var initWinFwd = 0; var initWinBwd = 0
        var initWinFwdSet = false; var initWinBwdSet = false

        // active / idle tracking
        val activePeriods = mutableListOf<Double>()
        val idlePeriods   = mutableListOf<Double>()
        private val IDLE_THRESHOLD_US = 1_000_000L   // 1 s gap = idle period
        var lastActiveStart = first.timestampUs

        // flow teardown
        var isClosed = false

        // app / TLS
        var appPackage   = ""
        var tlsSni       = ""
        var isEncrypted  = false

        // bulk tracking (simplified)
        var fwdBulkBytes = 0L; var fwdBulkPackets = 0L; var fwdBulkCount = 0L
        var bwdBulkBytes = 0L; var bwdBulkPackets = 0L; var bwdBulkCount = 0L
        private var fwdBulkStreakBytes = 0L; private var fwdBulkStreakPkts = 0L
        private var bwdBulkStreakBytes = 0L; private var bwdBulkStreakPkts = 0L

        // act data packets
        var actDataPktFwd = 0L
        val fwdSegSizes   = mutableListOf<Int>()

        init { add(first) }

        fun isFwd(p: ParsedPacket) = p.srcIp == fwdSrcIp && p.srcPort == fwdSrcPort

        fun add(p: ParsedPacket) {
            lastSeenUs = p.timestampUs
            val len = p.totalLength.toDouble()
            allLengths.add(len)

            // IAT for all packets
            val allIat = (p.timestampUs - lastAllTs).toDouble()
            if (lastAllTs > 0 && allIat >= 0) allIats.add(allIat)
            lastAllTs = p.timestampUs

            // Active/Idle
            if (allIat > IDLE_THRESHOLD_US) {
                activePeriods.add((lastSeenUs - lastActiveStart).toDouble())
                idlePeriods.add(allIat)
                lastActiveStart = p.timestampUs
            }

            val isFwd = isFwd(p)
            if (isFwd) {
                fwdLengths.add(len)
                if (lastFwdTs > 0) fwdIats.add((p.timestampUs - lastFwdTs).toDouble())
                lastFwdTs = p.timestampUs
                fwdHeaderBytes += p.ipHeaderLength + p.tcpHeaderLength
                if (p.isTcp) {
                    if (p.flagPsh) fwdPsh++
                    if (p.flagUrg) fwdUrg++
                    if (!initWinFwdSet) { initWinFwd = p.tcpWindowSize; initWinFwdSet = true }
                }
                if (p.payloadLength > 0) {
                    actDataPktFwd++
                    fwdSegSizes.add(p.payloadLength)
                    fwdBulkStreakBytes += p.payloadLength
                    fwdBulkStreakPkts++
                } else {
                    if (fwdBulkStreakPkts >= 4) {
                        fwdBulkBytes += fwdBulkStreakBytes
                        fwdBulkPackets += fwdBulkStreakPkts
                        fwdBulkCount++
                    }
                    fwdBulkStreakBytes = 0; fwdBulkStreakPkts = 0
                }
            } else {
                bwdLengths.add(len)
                if (lastBwdTs > 0) bwdIats.add((p.timestampUs - lastBwdTs).toDouble())
                lastBwdTs = p.timestampUs
                bwdHeaderBytes += p.ipHeaderLength + p.tcpHeaderLength
                if (p.isTcp) {
                    if (p.flagPsh) bwdPsh++
                    if (p.flagUrg) bwdUrg++
                    if (!initWinBwdSet) { initWinBwd = p.tcpWindowSize; initWinBwdSet = true }
                }
                if (p.payloadLength > 0) {
                    bwdBulkStreakBytes += p.payloadLength
                    bwdBulkStreakPkts++
                } else {
                    if (bwdBulkStreakPkts >= 4) {
                        bwdBulkBytes += bwdBulkStreakBytes
                        bwdBulkPackets += bwdBulkStreakPkts
                        bwdBulkCount++
                    }
                    bwdBulkStreakBytes = 0; bwdBulkStreakPkts = 0
                }
            }

            // TCP flags
            if (p.isTcp) {
                if (p.flagFin) { finCount++; if (isFwd) isClosed = true }
                if (p.flagSyn) synCount++
                if (p.flagRst) { rstCount++; isClosed = true }
                if (p.flagPsh) pshCount++
                if (p.flagAck) ackCount++
                if (p.flagUrg) urgCount++
                if (p.flagCwe) cweCount++
                if (p.flagEce) eceCount++
            }

            if (p.tlsSni.isNotEmpty()) tlsSni = p.tlsSni
            if (p.isEncrypted) isEncrypted = true
        }

        fun toRecord(): FlowRecord {
            val durationUs = max(1L, lastSeenUs - startUs)
            val durationS  = durationUs / 1_000_000.0

            val fwdBytes = fwdLengths.sumOf { it.toLong() }
            val bwdBytes = bwdLengths.sumOf { it.toLong() }
            val totalBytes = fwdBytes + bwdBytes

            val fwdPkts  = fwdLengths.size.toLong()
            val bwdPkts  = bwdLengths.size.toLong()
            val allPkts  = allLengths.size.toLong()

            val downUp   = if (fwdBytes > 0) bwdBytes.toDouble() / fwdBytes else 0.0

            return FlowRecord(
                flowId              = "${fwdSrcIp}:${fwdSrcPort}->${fwdDstIp}:${fwdDstPort}@${startUs}",
                captureTimestamp    = System.currentTimeMillis(),
                protocol            = protocol,
                protocolName        = protocolName,
                srcIp               = fwdSrcIp,
                dstIp               = fwdDstIp,
                srcPort             = fwdSrcPort,
                dstPort             = fwdDstPort,
                destinationPort     = fwdDstPort,
                flowDurationUs      = durationUs,

                totalFwdPackets     = fwdPkts,
                totalBwdPackets     = bwdPkts,
                totalPackets        = allPkts,
                totalLengthFwdPackets = fwdBytes,
                totalLengthBwdPackets = bwdBytes,

                packetLengthMax     = allLengths.maxOrNull() ?: 0.0,
                packetLengthMin     = allLengths.minOrNull() ?: 0.0,
                packetLengthMean    = allLengths.mean(),
                packetLengthStd     = allLengths.std(),
                packetLengthVariance= allLengths.variance(),

                fwdPacketLengthMax  = fwdLengths.maxOrNull() ?: 0.0,
                fwdPacketLengthMin  = fwdLengths.minOrNull() ?: 0.0,
                fwdPacketLengthMean = fwdLengths.mean(),
                fwdPacketLengthStd  = fwdLengths.std(),

                bwdPacketLengthMax  = bwdLengths.maxOrNull() ?: 0.0,
                bwdPacketLengthMin  = bwdLengths.minOrNull() ?: 0.0,
                bwdPacketLengthMean = bwdLengths.mean(),
                bwdPacketLengthStd  = bwdLengths.std(),

                flowBytesPerSec     = totalBytes / durationS,
                flowPacketsPerSec   = allPkts / durationS,
                fwdPacketsPerSec    = fwdPkts / durationS,
                bwdPacketsPerSec    = bwdPkts / durationS,

                flowIatMean = allIats.mean(), flowIatStd = allIats.std(),
                flowIatMax  = allIats.maxOrNull() ?: 0.0,
                flowIatMin  = allIats.minOrNull() ?: 0.0,

                fwdIatTotal = fwdIats.sum(),
                fwdIatMean  = fwdIats.mean(), fwdIatStd = fwdIats.std(),
                fwdIatMax   = fwdIats.maxOrNull() ?: 0.0,
                fwdIatMin   = fwdIats.minOrNull() ?: 0.0,

                bwdIatTotal = bwdIats.sum(),
                bwdIatMean  = bwdIats.mean(), bwdIatStd = bwdIats.std(),
                bwdIatMax   = bwdIats.maxOrNull() ?: 0.0,
                bwdIatMin   = bwdIats.minOrNull() ?: 0.0,

                fwdPshFlags = fwdPsh, fwdUrgFlags = fwdUrg,
                fwdHeaderLength = fwdHeaderBytes,
                bwdPshFlags = bwdPsh, bwdUrgFlags = bwdUrg,
                bwdHeaderLength = bwdHeaderBytes,

                finFlagCount = finCount, synFlagCount = synCount,
                rstFlagCount = rstCount, pshFlagCount = pshCount,
                ackFlagCount = ackCount, urgFlagCount = urgCount,
                cweFlagCount = cweCount, eceFlagCount = eceCount,

                downUpRatio         = downUp,
                avgPacketSize       = totalBytes.toDouble() / max(1, allPkts),
                avgFwdSegmentSize   = fwdLengths.mean(),
                avgBwdSegmentSize   = bwdLengths.mean(),

                fwdAvgBytesBulk     = if (fwdBulkCount > 0) fwdBulkBytes.toDouble() / fwdBulkCount else 0.0,
                fwdAvgPacketsBulk   = if (fwdBulkCount > 0) fwdBulkPackets.toDouble() / fwdBulkCount else 0.0,
                fwdAvgBulkRate      = if (durationS > 0) fwdBulkBytes / durationS else 0.0,
                bwdAvgBytesBulk     = if (bwdBulkCount > 0) bwdBulkBytes.toDouble() / bwdBulkCount else 0.0,
                bwdAvgPacketsBulk   = if (bwdBulkCount > 0) bwdBulkPackets.toDouble() / bwdBulkCount else 0.0,
                bwdAvgBulkRate      = if (durationS > 0) bwdBulkBytes / durationS else 0.0,

                subflowFwdPackets   = fwdPkts,
                subflowFwdBytes     = fwdBytes,
                subflowBwdPackets   = bwdPkts,
                subflowBwdBytes     = bwdBytes,

                initWinBytesFwd     = initWinFwd,
                initWinBytesBwd     = initWinBwd,

                activeMin  = activePeriods.minOrNull() ?: 0.0,
                activeMean = activePeriods.mean(),
                activeMax  = activePeriods.maxOrNull() ?: 0.0,
                activeStd  = activePeriods.std(),
                idleMin    = idlePeriods.minOrNull() ?: 0.0,
                idleMean   = idlePeriods.mean(),
                idleMax    = idlePeriods.maxOrNull() ?: 0.0,
                idleStd    = idlePeriods.std(),

                actDataPktFwd  = actDataPktFwd,
                minSegSizeFwd  = fwdSegSizes.minOrNull() ?: 0,

                appPackageName = appPackage,
                isEncrypted    = isEncrypted,
                tlsSni         = tlsSni,
                predictedLabel = "UNCLASSIFIED"
            )
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    private val flows = LinkedHashMap<FlowKey, FlowAccumulator>()

    /** Feed one parsed packet into the tracker. */
    fun feed(packet: ParsedPacket) {
        val key = packetKey(packet)

        val acc = flows.getOrPut(key) {
            if (flows.size >= maxFlows) evictOldest()
            FlowAccumulator(packet)
        }

        acc.add(packet)

        // Finalise on TCP teardown
        if (packet.isTcp && (packet.flagRst || (acc.isClosed && packet.flagAck))) {
            flows.remove(key)
            onFlowComplete(acc.toRecord())
        }
    }

    /**
     * Call periodically (e.g. every 10 s) to expire idle flows.
     * [nowUs] = System.nanoTime() / 1000
     */
    fun evictIdle(nowUs: Long) {
        val toEvict = flows.entries
            .filter { (_, acc) -> (nowUs - acc.lastSeenUs) > idleTimeoutUs }
            .map { it.key }
        toEvict.forEach { k ->
            val acc = flows.remove(k) ?: return@forEach
            onFlowComplete(acc.toRecord())
        }
    }

    /** Flush all remaining flows (e.g. on service stop). */
    fun flushAll() {
        flows.values.forEach { onFlowComplete(it.toRecord()) }
        flows.clear()
    }

    private fun evictOldest() {
        val oldest = flows.entries.minByOrNull { it.value.lastSeenUs } ?: return
        flows.remove(oldest.key)
        onFlowComplete(oldest.value.toRecord())
    }

    // ── Statistics helpers ────────────────────────────────────────────────────

    private fun List<Double>.mean(): Double =
        if (isEmpty()) 0.0 else sum() / size

    private fun List<Double>.variance(): Double {
        if (size < 2) return 0.0
        val m = mean()
        return sumOf { (it - m) * (it - m) } / size
    }

    private fun List<Double>.std(): Double = sqrt(variance())
}
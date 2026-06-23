package com.muhammad.networkscan.classifier


import com.muhammad.networkscan.live_traffic.Confidence
import com.muhammad.networkscan.live_traffic.SourceActivityWindow
import com.muhammad.networkscan.live_traffic.TrafficCategory
import com.muhammad.networkscan.live_traffic.TrafficVerdict
import com.muhammad.networkscan.models.NetworkFlow
import java.util.concurrent.ConcurrentHashMap



class HeuristicTrafficClassifier {

    companion object {
        private const val WINDOW_MS = 10_000L

        private const val PORT_SCAN_PORT_THRESHOLD_MEDIUM = 12
        private const val PORT_SCAN_PORT_THRESHOLD_HIGH = 25

        private const val HOST_DISCOVERY_IP_THRESHOLD_MEDIUM = 18
        private const val HOST_DISCOVERY_IP_THRESHOLD_HIGH = 30

        private const val SYN_FLOOD_COUNT_THRESHOLD_MEDIUM = 60
        private const val SYN_FLOOD_COUNT_THRESHOLD_HIGH = 120
        private const val SYN_FLOOD_MIN_DISTINCT_TARGETS_FOR_HIGH_CONFIDENCE = 3

        private const val FLOOD_PACKETS_PER_SEC_THRESHOLD = 200.0
        private const val FLOOD_BYTES_PER_SEC_THRESHOLD = 2_000_000.0

        private const val BRUTE_FORCE_REPEAT_THRESHOLD = 3

        private val CREDENTIAL_PORTS = setOf(
            21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900
        )

        private val KNOWN_DNS_SERVERS = setOf(
            "8.8.8.8", "8.8.4.4",
            "1.1.1.1", "1.0.0.1",
            "9.9.9.9",
            "208.67.222.222", "208.67.220.220"
        )
    }

    private val sourceWindows = ConcurrentHashMap<String, SourceActivityWindow>()

    fun classify(flow: NetworkFlow): TrafficVerdict {
        val window = sourceWindows.getOrPut(flow.srcIp) { SourceActivityWindow(WINDOW_MS) }
        window.record(flow)

        val nowMs = flow.lastSeenMs

        val distinctPorts = window.distinctPortCount(nowMs)
        val distinctIps = window.distinctIpCount(nowMs)
        val totalSyn = window.totalSynCount(nowMs)
        val repeatedTargets = window.repeatedTargetCount(nowMs)
        val singlePacketFlows = window.singlePacketFlowCount(nowMs)
        val distinctSynTargets = window.distinctSynTargetCount(nowMs)

        val isKnownDns = flow.dstPort == 53 && flow.protocol == "UDP" && flow.dstIp in KNOWN_DNS_SERVERS
        val isDnsLike = flow.dstPort == 53 && flow.protocol == "UDP"

        var category = TrafficCategory.BENIGN
        var confidence = Confidence.LOW
        var reason = "No suspicious pattern matched"

        if (distinctPorts >= PORT_SCAN_PORT_THRESHOLD_HIGH && singlePacketFlows >= PORT_SCAN_PORT_THRESHOLD_HIGH / 2) {
            category = TrafficCategory.PORT_SCAN
            confidence = Confidence.HIGH
            reason = "Source contacted $distinctPorts distinct ports in the last 10s, mostly single-packet probes ($singlePacketFlows flows)"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (distinctPorts >= PORT_SCAN_PORT_THRESHOLD_MEDIUM) {
            category = TrafficCategory.PORT_SCAN
            confidence = Confidence.MEDIUM
            reason = "Source contacted $distinctPorts distinct ports in the last 10s"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (distinctIps >= HOST_DISCOVERY_IP_THRESHOLD_HIGH) {
            category = TrafficCategory.HOST_DISCOVERY
            confidence = Confidence.HIGH
            reason = "Source contacted $distinctIps distinct destination IPs in the last 10s"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (distinctIps >= HOST_DISCOVERY_IP_THRESHOLD_MEDIUM) {
            category = TrafficCategory.HOST_DISCOVERY
            confidence = Confidence.MEDIUM
            reason = "Source contacted $distinctIps distinct destination IPs in the last 10s"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (totalSyn >= SYN_FLOOD_COUNT_THRESHOLD_HIGH &&
            distinctSynTargets >= SYN_FLOOD_MIN_DISTINCT_TARGETS_FOR_HIGH_CONFIDENCE) {
            category = TrafficCategory.SYN_FLOOD
            confidence = Confidence.HIGH
            reason = "$totalSyn SYN flags observed from this source across $distinctSynTargets distinct destinations in the last 10s, with no completed handshakes"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (totalSyn >= SYN_FLOOD_COUNT_THRESHOLD_MEDIUM) {
            category = TrafficCategory.SYN_FLOOD
            confidence = Confidence.LOW
            reason = "$totalSyn SYN flags observed from this source in the last 10s (to $distinctSynTargets destination(s) — could be normal parallel connection setup)"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (flow.dstPort in CREDENTIAL_PORTS &&
            repeatedTargets >= BRUTE_FORCE_REPEAT_THRESHOLD - 2 &&
            flow.protocol == "TCP") {
            category = TrafficCategory.BRUTE_FORCE_PATTERN
            confidence = if (repeatedTargets >= BRUTE_FORCE_REPEAT_THRESHOLD) Confidence.MEDIUM else Confidence.LOW
            reason = "Repeated short connections to ${flow.dstIp}:${flow.dstPort} (credential/authentication service port)"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if(flow.durationMs >= 1000 && flow.totalPackets >= 20 &&
            (flow.packetsPerSecond >= FLOOD_PACKETS_PER_SEC_THRESHOLD ||
                    flow.bytesPerSecond >= FLOOD_BYTES_PER_SEC_THRESHOLD)) {
            category = TrafficCategory.GENERIC_FLOOD
            confidence = Confidence.MEDIUM
            reason = "Single flow sustained ${"%.0f".format(flow.packetsPerSecond)} pkt/s / ${"%.0f".format(flow.bytesPerSecond)} B/s — far above typical mobile app traffic"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (isDnsLike && !isKnownDns) {
            category = TrafficCategory.SUSPICIOUS_DNS
            confidence = Confidence.LOW
            reason = "DNS query (port 53) to ${flow.dstIp}, which is not a recognized public resolver — could be local/ISP/router DNS or a spoofed resolver"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (isKnownDns) {
            category = TrafficCategory.BENIGN
            confidence = Confidence.MEDIUM
            reason = "Known DNS resolver and normal DNS pattern"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        if (flow.protocol == "TCP" && flow.dstPort in setOf(443, 80, 853, 5222) && flow.totalPackets <= 3) {
            category = TrafficCategory.BENIGN
            confidence = Confidence.LOW
            reason = "Common mobile app destination with sparse flow"
            return TrafficVerdict(flow.flowId, category, confidence, reason)
        }

        return TrafficVerdict(flow.flowId, category, confidence, reason)
    }

    fun reset() {
        sourceWindows.clear()
    }
}
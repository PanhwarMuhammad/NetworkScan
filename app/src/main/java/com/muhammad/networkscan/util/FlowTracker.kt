package com.muhammad.networkscan.util

import com.muhammad.networkscan.util.PacketParser
import com.muhammad.networkscan.models.NetworkFlow
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class FlowTracker {

    companion object {
        private const val FLOW_TIMEOUT_MS = 60_000L
        private const val FLOW_MAX_DURATION_MS = 600_000L
    }

    private val activeFlows = ConcurrentHashMap<String, NetworkFlow>()

    private val completedFlows = mutableListOf<NetworkFlow>()
    private val completedLock = Any()

    fun processPacket(packet: PacketParser.ParsedPacket, nowMs: Long) {
        val key = buildKey(packet)
        val flow = activeFlows.getOrPut(key) {
            NetworkFlow(
                flowId = UUID.randomUUID().toString().substring(0, 8),
                protocol = PacketParser.protocolName(packet.protocol),
                srcIp = packet.srcIp,
                dstIp = packet.dstIp,
                srcPort = packet.srcPort,
                dstPort = packet.dstPort,
                startTimeMs = nowMs,
                lastSeenMs = nowMs
            )
        }

        synchronized(flow) {
            flow.lastSeenMs = nowMs
            flow.totalPackets++
            flow.totalBytes += packet.totalLength
            flow.fwdPackets++
            flow.fwdBytes += packet.totalLength

            val pktLen = packet.totalLength
            if (pktLen < flow.minPacketLen) flow.minPacketLen = pktLen
            if (pktLen > flow.maxPacketLen) flow.maxPacketLen = pktLen

            if (packet.protocol == PacketParser.PROTO_TCP) {
                flow.tcpFlags = flow.tcpFlags or packet.tcpFlags
                if (packet.tcpFlags and PacketParser.FLAG_FIN != 0) flow.finCount++
                if (packet.tcpFlags and PacketParser.FLAG_SYN != 0) flow.synCount++
                if (packet.tcpFlags and PacketParser.FLAG_RST != 0) flow.rstCount++
                if (packet.tcpFlags and PacketParser.FLAG_PSH != 0) flow.pshCount++
                if (packet.tcpFlags and PacketParser.FLAG_ACK != 0) flow.ackCount++
                if (packet.tcpFlags and PacketParser.FLAG_URG != 0) flow.urgCount++
            }
        }
    }

    fun expireFlows(nowMs: Long): List<NetworkFlow> {
        val keysToRemove = mutableListOf<String>()

        for ((key, flow) in activeFlows) {
            val idle = nowMs - flow.lastSeenMs
            val duration = nowMs - flow.startTimeMs
            if (idle > FLOW_TIMEOUT_MS || duration > FLOW_MAX_DURATION_MS) {
                keysToRemove.add(key)
            }
        }

        val justExpired = mutableListOf<NetworkFlow>()
        for (key in keysToRemove) {
            activeFlows.remove(key)?.let { flow ->
                synchronized(completedLock) {
                    completedFlows.add(flow)
                }
                justExpired.add(flow)
            }
        }
        return justExpired
    }

    fun finalizeAll(): List<NetworkFlow> {
        val all = mutableListOf<NetworkFlow>()
        for ((_, flow) in activeFlows) {
            all.add(flow)
        }
        activeFlows.clear()
        synchronized(completedLock) {
            all.addAll(completedFlows)
            completedFlows.clear()
        }
        return all
    }

    fun getActiveFlowCount(): Int = activeFlows.size

    fun getCompletedFlowCount(): Int = synchronized(completedLock) { completedFlows.size }

    fun getTotalFlowCount(): Int = getActiveFlowCount() + getCompletedFlowCount()

    private fun buildKey(p: PacketParser.ParsedPacket): String =
        "${p.protocol}_${p.srcIp}:${p.srcPort}->${p.dstIp}:${p.dstPort}"
}

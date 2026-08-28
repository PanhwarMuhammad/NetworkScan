package com.muhammad.networkscan.models

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken


@Entity(tableName = "flow_records")
@TypeConverters(FlowRecordConverters::class)

data class FlowRecord(

    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    val flowId: String = "",
    val captureTimestamp: Long = 0L,

    val protocol: Int = 0,            // 6=TCP, 17=UDP, 1=ICMP
    val protocolName: String = "",    // "TCP" / "UDP" / "ICMP" / "OTHER"
    val srcIp: String = "",
    val dstIp: String = "",
    val srcPort: Int = 0,
    val dstPort: Int = 0,
    val destinationPort: Int = 0,     // alias kept for DT feature name compatibility

    val flowDurationUs: Long = 0L,    // microseconds (feature: Flow Duration)

    val totalFwdPackets: Long = 0L,
    val totalBwdPackets: Long = 0L,
    val totalPackets: Long = 0L,

    val totalLengthFwdPackets: Long = 0L,
    val totalLengthBwdPackets: Long = 0L,

    val packetLengthMax: Double = 0.0,
    val packetLengthMin: Double = 0.0,
    val packetLengthMean: Double = 0.0,
    val packetLengthStd: Double = 0.0,
    val packetLengthVariance: Double = 0.0,

    val fwdPacketLengthMax: Double = 0.0,
    val fwdPacketLengthMin: Double = 0.0,
    val fwdPacketLengthMean: Double = 0.0,
    val fwdPacketLengthStd: Double = 0.0,

    val bwdPacketLengthMax: Double = 0.0,
    val bwdPacketLengthMin: Double = 0.0,
    val bwdPacketLengthMean: Double = 0.0,
    val bwdPacketLengthStd: Double = 0.0,

    val flowBytesPerSec: Double = 0.0,
    val flowPacketsPerSec: Double = 0.0,
    val fwdPacketsPerSec: Double = 0.0,
    val bwdPacketsPerSec: Double = 0.0,

    val flowIatMean: Double = 0.0,
    val flowIatStd: Double = 0.0,
    val flowIatMax: Double = 0.0,
    val flowIatMin: Double = 0.0,

    val fwdIatTotal: Double = 0.0,
    val fwdIatMean: Double = 0.0,
    val fwdIatStd: Double = 0.0,
    val fwdIatMax: Double = 0.0,
    val fwdIatMin: Double = 0.0,

    val bwdIatTotal: Double = 0.0,
    val bwdIatMean: Double = 0.0,
    val bwdIatStd: Double = 0.0,
    val bwdIatMax: Double = 0.0,
    val bwdIatMin: Double = 0.0,

    val fwdPshFlags: Int = 0,
    val fwdUrgFlags: Int = 0,
    val fwdHeaderLength: Long = 0L,

    val bwdPshFlags: Int = 0,
    val bwdUrgFlags: Int = 0,
    val bwdHeaderLength: Long = 0L,

    val finFlagCount: Int = 0,
    val synFlagCount: Int = 0,
    val rstFlagCount: Int = 0,
    val pshFlagCount: Int = 0,
    val ackFlagCount: Int = 0,
    val urgFlagCount: Int = 0,
    val cweFlagCount: Int = 0,
    val eceFlagCount: Int = 0,

    val downUpRatio: Double = 0.0,           // bwd bytes / fwd bytes
    val avgPacketSize: Double = 0.0,
    val avgFwdSegmentSize: Double = 0.0,
    val avgBwdSegmentSize: Double = 0.0,

    val fwdAvgBytesBulk: Double = 0.0,
    val fwdAvgPacketsBulk: Double = 0.0,
    val fwdAvgBulkRate: Double = 0.0,
    val bwdAvgBytesBulk: Double = 0.0,
    val bwdAvgPacketsBulk: Double = 0.0,
    val bwdAvgBulkRate: Double = 0.0,

    val subflowFwdPackets: Long = 0L,
    val subflowFwdBytes: Long = 0L,
    val subflowBwdPackets: Long = 0L,
    val subflowBwdBytes: Long = 0L,

    val initWinBytesFwd: Int = 0,
    val initWinBytesBwd: Int = 0,

    val activeMin: Double = 0.0,
    val activeMean: Double = 0.0,
    val activeMax: Double = 0.0,
    val activeStd: Double = 0.0,
    val idleMin: Double = 0.0,
    val idleMean: Double = 0.0,
    val idleMax: Double = 0.0,
    val idleStd: Double = 0.0,

    val actDataPktFwd: Long = 0L,
    val minSegSizeFwd: Int = 0,

    // Extras available from VpnService
    val appPackageName: String = "",
    val isEncrypted: Boolean = false,   // dstPort 443 / 853 / 8443 etc.
    val tlsSni: String = "",

    val predictedLabel: String = "UNCLASSIFIED",
    val confidence: Float = 0f,
    val isFlagged: Boolean = false
)

class FlowRecordConverters {
    private val gson = Gson()

    @TypeConverter fun listToJson(v: List<Double>): String = gson.toJson(v)
    @TypeConverter fun jsonToList(v: String): List<Double> =
        gson.fromJson(v, object : TypeToken<List<Double>>() {}.type) ?: emptyList()
}

fun FlowRecord.toCsvRow(): String = listOf(
    id, flowId, captureTimestamp, protocol, protocolName,
    srcIp, dstIp, srcPort, dstPort, destinationPort,
    flowDurationUs, totalFwdPackets, totalBwdPackets, totalPackets,
    totalLengthFwdPackets, totalLengthBwdPackets,
    packetLengthMax, packetLengthMin, packetLengthMean, packetLengthStd, packetLengthVariance,
    fwdPacketLengthMax, fwdPacketLengthMin, fwdPacketLengthMean, fwdPacketLengthStd,
    bwdPacketLengthMax, bwdPacketLengthMin, bwdPacketLengthMean, bwdPacketLengthStd,
    flowBytesPerSec, flowPacketsPerSec, fwdPacketsPerSec, bwdPacketsPerSec,
    flowIatMean, flowIatStd, flowIatMax, flowIatMin,
    fwdIatTotal, fwdIatMean, fwdIatStd, fwdIatMax, fwdIatMin,
    bwdIatTotal, bwdIatMean, bwdIatStd, bwdIatMax, bwdIatMin,
    fwdPshFlags, fwdUrgFlags, fwdHeaderLength,
    bwdPshFlags, bwdUrgFlags, bwdHeaderLength,
    finFlagCount, synFlagCount, rstFlagCount, pshFlagCount,
    ackFlagCount, urgFlagCount, cweFlagCount, eceFlagCount,
    downUpRatio, avgPacketSize, avgFwdSegmentSize, avgBwdSegmentSize,
    fwdAvgBytesBulk, fwdAvgPacketsBulk, fwdAvgBulkRate,
    bwdAvgBytesBulk, bwdAvgPacketsBulk, bwdAvgBulkRate,
    subflowFwdPackets, subflowFwdBytes, subflowBwdPackets, subflowBwdBytes,
    initWinBytesFwd, initWinBytesBwd,
    activeMin, activeMean, activeMax, activeStd,
    idleMin, idleMean, idleMax, idleStd,
    actDataPktFwd, minSegSizeFwd,
    appPackageName, isEncrypted, tlsSni,
    predictedLabel, confidence, isFlagged
).joinToString(",") { it.toString().replace(",", ";") }

val CSV_HEADER = listOf(
    "id","flow_id","capture_timestamp","protocol","protocol_name",
    "src_ip","dst_ip","src_port","dst_port","destination_port",
    "flow_duration_us","total_fwd_packets","total_bwd_packets","total_packets",
    "total_len_fwd_pkts","total_len_bwd_pkts",
    "pkt_len_max","pkt_len_min","pkt_len_mean","pkt_len_std","pkt_len_var",
    "fwd_pkt_len_max","fwd_pkt_len_min","fwd_pkt_len_mean","fwd_pkt_len_std",
    "bwd_pkt_len_max","bwd_pkt_len_min","bwd_pkt_len_mean","bwd_pkt_len_std",
    "flow_bytes_per_s","flow_pkts_per_s","fwd_pkts_per_s","bwd_pkts_per_s",
    "flow_iat_mean","flow_iat_std","flow_iat_max","flow_iat_min",
    "fwd_iat_tot","fwd_iat_mean","fwd_iat_std","fwd_iat_max","fwd_iat_min",
    "bwd_iat_tot","bwd_iat_mean","bwd_iat_std","bwd_iat_max","bwd_iat_min",
    "fwd_psh_flags","fwd_urg_flags","fwd_header_len",
    "bwd_psh_flags","bwd_urg_flags","bwd_header_len",
    "fin_flag_cnt","syn_flag_cnt","rst_flag_cnt","psh_flag_cnt",
    "ack_flag_cnt","urg_flag_cnt","cwe_flag_cnt","ece_flag_cnt",
    "down_up_ratio","avg_pkt_size","avg_fwd_seg_size","avg_bwd_seg_size",
    "fwd_avg_bytes_bulk","fwd_avg_pkts_bulk","fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk","bwd_avg_pkts_bulk","bwd_avg_bulk_rate",
    "subflow_fwd_pkts","subflow_fwd_bytes","subflow_bwd_pkts","subflow_bwd_bytes",
    "init_win_bytes_fwd","init_win_bytes_bwd",
    "active_min","active_mean","active_max","active_std",
    "idle_min","idle_mean","idle_max","idle_std",
    "act_data_pkt_fwd","min_seg_size_fwd",
    "app_package","is_encrypted","tls_sni",
    "predicted_label","confidence","is_flagged"
).joinToString(",")
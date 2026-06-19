package com.muhammad.networkscan.adapter


import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.muhammad.networkscan.R
import com.muhammad.networkscan.models.FlowRecord
import java.text.SimpleDateFormat
import java.util.*

// ─────────────────────────────────────────────────────────────────────────────
// CaptureAdapter.kt
// ─────────────────────────────────────────────────────────────────────────────

class CaptureAdapter(
    private val onItemClick: (FlowRecord) -> Unit
) : ListAdapter<FlowRecord, CaptureAdapter.ViewHolder>(DIFF) {

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<FlowRecord>() {
            override fun areItemsTheSame(a: FlowRecord, b: FlowRecord) = a.id == b.id
            override fun areContentsTheSame(a: FlowRecord, b: FlowRecord) = a == b
        }
        private val DATE_FMT = SimpleDateFormat("HH:mm:ss", Locale.US)
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvProtocol:   TextView  = view.findViewById(R.id.tv_protocol)
        val tvDirection:  TextView  = view.findViewById(R.id.tv_direction)
        val tvTimestamp:  TextView  = view.findViewById(R.id.tv_timestamp)
        val tvPackets:    TextView  = view.findViewById(R.id.tv_packets)
        val tvBytes:      TextView  = view.findViewById(R.id.tv_bytes)
        val tvDuration:   TextView  = view.findViewById(R.id.tv_duration)
        val tvLabel:      TextView  = view.findViewById(R.id.tv_label)
        val ivEncrypted:  ImageView = view.findViewById(R.id.iv_encrypted)
        val ivFlag:       ImageView = view.findViewById(R.id.iv_flag)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_flow_record, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val record = getItem(position)
        val ctx    = holder.itemView.context

        holder.tvProtocol.text  = record.protocolName
        holder.tvTimestamp.text = DATE_FMT.format(Date(record.captureTimestamp))
        holder.tvPackets.text   = "${record.totalPackets} pkts"
        holder.tvBytes.text     = formatBytes(record.totalLengthFwdPackets + record.totalLengthBwdPackets)
        holder.tvDuration.text  = formatDuration(record.flowDurationUs)
        holder.tvLabel.text     = record.predictedLabel
        holder.tvDirection.text = "${record.srcIp.substringAfterLast('.')}:${record.srcPort} → " +
                "${record.dstIp.substringAfterLast('.')}:${record.dstPort}"

        holder.ivEncrypted.visibility = if (record.isEncrypted) View.VISIBLE else View.GONE
        holder.ivFlag.visibility      = if (record.isFlagged)   View.VISIBLE else View.GONE

        // Protocol badge colour
        val badgeColor = when (record.protocolName) {
            "TCP"  -> R.color.proto_tcp
            "UDP"  -> R.color.proto_udp
            "ICMP" -> R.color.proto_icmp
            else   -> R.color.proto_other
        }
        holder.tvProtocol.setBackgroundColor(ContextCompat.getColor(ctx, badgeColor))

        holder.itemView.setOnClickListener { onItemClick(record) }
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1_000_000L -> "%.1f MB".format(bytes / 1_000_000.0)
        bytes >= 1_000L     -> "%.1f KB".format(bytes / 1_000.0)
        else                -> "$bytes B"
    }

    private fun formatDuration(us: Long): String = when {
        us >= 1_000_000L -> "%.2f s".format(us / 1_000_000.0)
        us >= 1_000L     -> "%.1f ms".format(us / 1_000.0)
        else             -> "$us µs"
    }
}
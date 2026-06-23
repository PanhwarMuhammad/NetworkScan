package com.muhammad.networkscan.adapter


import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.muhammad.networkscan.databinding.ItemLiveFlowBinding
import com.muhammad.networkscan.models.LiveFlowUiModel

class LiveFlowAdapter : ListAdapter<LiveFlowUiModel, LiveFlowAdapter.VH>(Diff) {

    object Diff : DiffUtil.ItemCallback<LiveFlowUiModel>() {
        override fun areItemsTheSame(oldItem: LiveFlowUiModel, newItem: LiveFlowUiModel) =
            oldItem.flowId == newItem.flowId

        override fun areContentsTheSame(oldItem: LiveFlowUiModel, newItem: LiveFlowUiModel) =
            oldItem == newItem
    }

    inner class VH(val binding: ItemLiveFlowBinding) : RecyclerView.ViewHolder(binding.root) {
        fun bind(item: LiveFlowUiModel) = with(binding) {
            tvTime.text = item.timeText
            tvFlowTitle.text = "${item.src} → ${item.dst}"
            tvProtocol.text = item.protocol
            tvCategory.text = item.category
            tvConfidence.text = item.confidence
            tvReason.text = item.reason
            chipAlert.text = if (item.isAlert) "ALERT" else "OK"
            chipAlert.isSelected = item.isAlert
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val binding = ItemLiveFlowBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(binding)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        holder.bind(getItem(position))
    }
}
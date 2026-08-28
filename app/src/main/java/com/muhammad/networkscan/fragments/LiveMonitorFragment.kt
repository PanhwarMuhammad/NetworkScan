package com.muhammad.networkscan.fragments

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.muhammad.networkscan.R

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter

import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.muhammad.networkscan.adapter.LiveFlowAdapter
import com.muhammad.networkscan.databinding.FragmentLiveMonitorBinding
import com.muhammad.networkscan.models.LiveFlowUiModel
import com.muhammad.networkscan.util.TrafficCaptureService

class LiveMonitorFragment : Fragment() {

    private var _binding: FragmentLiveMonitorBinding? = null
    private val binding get() = _binding!!

    private val adapter = LiveFlowAdapter()
    private val items = mutableListOf<LiveFlowUiModel>()

    private val flowReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != TrafficCaptureService.BROADCAST_FLOW_EVENT) return

            val item = LiveFlowUiModel(
                flowId = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_ID) ?: return,
                timeText = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_TIME) ?: "--:--:--",
                src = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_SRC) ?: "",
                dst = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_DST) ?: "",
                protocol = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_PROTOCOL) ?: "",
                category = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_CATEGORY) ?: "",
                confidence = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_CONFIDENCE) ?: "",
                reason = intent.getStringExtra(TrafficCaptureService.EXTRA_FLOW_REASON) ?: "",
                isAlert = intent.getBooleanExtra(TrafficCaptureService.EXTRA_FLOW_ALERT, false)
            )

            items.add(0, item)
            adapter.submitList(items.toList())
            updateSummary()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentLiveMonitorBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        binding.recyclerLiveFlows.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerLiveFlows.adapter = adapter
        updateSummary()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(TrafficCaptureService.BROADCAST_FLOW_EVENT)
        ContextCompat.registerReceiver(
            requireContext(),
            flowReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    override fun onStop() {
        super.onStop()
        requireContext().unregisterReceiver(flowReceiver)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private fun updateSummary() {
        if (_binding == null) return


        val alertCount = items.count { it.isAlert }
        val benignCount = items.size - alertCount

        binding.tvLiveFlows.text = items.size.toString()
        binding.tvLivePackets.text = "--"
        binding.tvLiveBytes.text = "--"

        binding.tvThreatSummary.text =
            "Threat summary: $benignCount benign, $alertCount suspicious. Showing most recent finalized flows."

        val color = if (alertCount > 0) R.color.capture_stop else R.color.capture_active
        binding.tvLiveStatus.setTextColor(ContextCompat.getColor(requireContext(), color))
    }
}
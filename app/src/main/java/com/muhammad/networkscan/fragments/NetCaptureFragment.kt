package com.muhammad.networkscan.fragments

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Bundle
import android.os.IBinder
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.muhammad.networkscan.R
import com.muhammad.networkscan.databinding.FragmentNetCaptureBinding
import com.muhammad.networkscan.util.TrafficCaptureService

class NetCaptureFragment : Fragment() {

    private var _binding: FragmentNetCaptureBinding? = null
    private val binding get() = _binding!!

    private var captureService: TrafficCaptureService? = null
    private var serviceBound = false

    // ── VPN permission launcher ────────────────────────────────────────────────
    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startService()
            } else {
                Toast.makeText(requireContext(),
                    "VPN permission denied — cannot capture traffic.",
                    Toast.LENGTH_LONG).show()
            }
        }

    // ── Service connection ─────────────────────────────────────────────────────
    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            captureService = (binder as TrafficCaptureService.LocalBinder).getService()
            serviceBound = true
            updateUiFromService()
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            captureService = null
            serviceBound = false
        }
    }

    // ── Stats broadcast receiver ───────────────────────────────────────────────
    private val statsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                TrafficCaptureService.BROADCAST_STATS -> {
                    val flows   = intent.getIntExtra(TrafficCaptureService.EXTRA_TOTAL_FLOWS, 0)
                    val packets = intent.getLongExtra(TrafficCaptureService.EXTRA_TOTAL_PACKETS, 0L)
                    val bytes   = intent.getLongExtra(TrafficCaptureService.EXTRA_TOTAL_BYTES, 0L)
                    val running = intent.getBooleanExtra(TrafficCaptureService.EXTRA_IS_RUNNING, false)
                    updateStats(flows, packets, bytes, running)
                }
                TrafficCaptureService.BROADCAST_SAVE_RESULT -> {
                    val success = intent.getBooleanExtra(TrafficCaptureService.EXTRA_SAVE_SUCCESS, false)
                    val msg     = intent.getStringExtra(TrafficCaptureService.EXTRA_SAVE_MESSAGE) ?: ""
                    showSaveResult(success, msg)
                }
            }
        }
    }

    // ── Fragment lifecycle ─────────────────────────────────────────────────────

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentNetCaptureBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setupClickListeners()
        updateUiState(isRunning = false)
    }

    override fun onStart() {
        super.onStart()
        // Bind to service if it's already running
        val bindIntent = Intent(requireContext(), TrafficCaptureService::class.java)
        requireContext().bindService(bindIntent, serviceConnection, Context.BIND_AUTO_CREATE)

        // Register broadcast receiver
        val filter = IntentFilter().apply {
            addAction(TrafficCaptureService.BROADCAST_STATS)
            addAction(TrafficCaptureService.BROADCAST_SAVE_RESULT)
        }
        ContextCompat.registerReceiver(
            requireContext(), statsReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    override fun onStop() {
        super.onStop()
        if (serviceBound) {
            requireContext().unbindService(serviceConnection)
            serviceBound = false
        }
        requireContext().unregisterReceiver(statsReceiver)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    // ── Click listeners ────────────────────────────────────────────────────────

    private fun setupClickListeners() {
        binding.btnStartStop.setOnClickListener {
            val service = captureService
            if (service != null && service.isRunning) {
                // Stop the service
                val intent = Intent(requireContext(), TrafficCaptureService::class.java).apply {
                    action = TrafficCaptureService.ACTION_STOP }
                requireContext().startService(intent)
                updateUiState(isRunning = false)
            } else {
                // Request VPN permission first
                val vpnIntent = VpnService.prepare(requireContext())
                if (vpnIntent != null) {
                    vpnPermissionLauncher.launch(vpnIntent)
                } else {
                    // Permission already granted
                    startService()
                }
            }
        }

        binding.btnSave.setOnClickListener {
            val service = captureService
            if (service != null) {
                binding.btnSave.isEnabled = false
                binding.btnSave.text = "Saving..."
                val intent = Intent(requireContext(), TrafficCaptureService::class.java).apply {
                    action = TrafficCaptureService.ACTION_SAVE }
                requireContext().startService(intent)
            } else {
                Toast.makeText(requireContext(), "No active capture session.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun startService() {
        val intent = Intent(requireContext(), TrafficCaptureService::class.java)
            .apply { action = TrafficCaptureService.ACTION_START }
        ContextCompat.startForegroundService(requireContext(), intent)
        updateUiState(isRunning = true)
        Toast.makeText(requireContext(), "Capture started.", Toast.LENGTH_SHORT).show()
    }

    private fun updateUiFromService() {
        val running = captureService?.isRunning ?: false
        updateUiState(running)
    }

    private fun updateUiState(isRunning: Boolean) {
        if (_binding == null) return
        if (isRunning) {
            binding.btnStartStop.text = "Stop & Save"
            binding.btnStartStop.setBackgroundColor(
                ContextCompat.getColor(requireContext(), R.color.capture_stop))
            binding.tvStatus.text = "● CAPTURING"
            binding.tvStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.capture_active))
            binding.btnSave.isEnabled = true
            binding.btnSave.text = "Save Now"
        } else {
            binding.btnStartStop.text = "Start Capture"
            binding.btnStartStop.setBackgroundColor(
                ContextCompat.getColor(requireContext(), R.color.capture_start))
            binding.tvStatus.text = "○ IDLE"
            binding.tvStatus.setTextColor(
                ContextCompat.getColor(requireContext(), R.color.capture_idle))
        }
    }

    private fun updateStats(flows: Int, packets: Long, bytes: Long, running: Boolean) {
        if (_binding == null) return
        updateUiState(running)
        binding.tvFlowCount.text = flows.toString()
        binding.tvPacketCount.text = packets.toString()
        binding.tvByteCount.text = formatBytes(bytes)
    }

    private fun showSaveResult(success: Boolean, message: String) {
        if (_binding == null) return
        binding.btnSave.isEnabled = true
        binding.btnSave.text = "Save Now"
        val color = if (success) R.color.capture_active else R.color.capture_stop
        binding.tvSaveResult.text = message
        binding.tvSaveResult.setTextColor(ContextCompat.getColor(requireContext(), color))
        binding.tvSaveResult.visibility = View.VISIBLE
        Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show()
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "${bytes} B"
        bytes < 1024 * 1024 -> "${"%.1f".format(bytes / 1024.0)} KB"
        else -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
    }
}

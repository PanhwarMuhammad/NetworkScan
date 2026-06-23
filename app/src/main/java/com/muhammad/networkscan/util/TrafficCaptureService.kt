package com.muhammad.networkscan.util

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.muhammad.networkscan.util.PacketParser
import com.muhammad.networkscan.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

import android.content.pm.ServiceInfo
import com.muhammad.networkscan.classifier.HeuristicTrafficClassifier
import com.muhammad.networkscan.live_traffic.TrafficVerdict
import java.nio.channels.FileChannel


class TrafficCaptureService : VpnService() {

    companion object {
        private const val TAG = "TrafficCaptureService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "netcapture_channel"
        private const val EXPIRE_INTERVAL_MS = 10_000L
        private const val MTU = 32767

        const val ACTION_START = "com.docutrack.netcapture.START"
        const val ACTION_STOP = "com.docutrack.netcapture.STOP"
        const val ACTION_SAVE = "com.docutrack.netcapture.SAVE"

        const val BROADCAST_STATS = "com.docutrack.netcapture.STATS"
        const val EXTRA_TOTAL_FLOWS = "total_flows"
        const val EXTRA_TOTAL_PACKETS = "total_packets"
        const val EXTRA_TOTAL_BYTES = "total_bytes"
        const val EXTRA_IS_RUNNING = "is_running"

        const val BROADCAST_SAVE_RESULT = "com.docutrack.netcapture.SAVE_RESULT"
        const val EXTRA_SAVE_SUCCESS = "save_success"
        const val EXTRA_SAVE_MESSAGE = "save_message"
    }

    inner class LocalBinder : Binder() {
        fun getService(): TrafficCaptureService = this@TrafficCaptureService
    }

    private val binder = LocalBinder()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var vpnInterface: ParcelFileDescriptor? = null
    private var captureJob: Job? = null
    private var expireJob: Job? = null
    private var statsJob: Job? = null
    private val flowTracker = FlowTracker()
    private val classifier = HeuristicTrafficClassifier()

    var isRunning = false
        private set
    var totalPackets = 0L
        private set
    var totalBytes = 0L
        private set

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startCapture()
            ACTION_STOP  -> stopCapture(autoSave = true)
            ACTION_SAVE  -> saveFlows()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopCapture(autoSave = true)
        serviceScope.cancel()
        super.onDestroy()
    }

    // ── Start / Stop ───────────────────────────────────────────────────────────

    fun startCapture() {
        if (isRunning) return
        Log.i(TAG, "Starting traffic capture (API ${Build.VERSION.SDK_INT})")

        val builder = Builder()
        builder.setMtu(MTU)
        builder.addAddress("10.0.0.2", 32)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("8.8.8.8")
        builder.addDnsServer("8.8.4.4")
        builder.setSession("NetCapture")

        // Exclude our own app from the tunnel to prevent a routing loop.
        // If we don't do this, network calls made by this service (e.g. during
        // export) get routed back into the tunnel causing a deadlock on Android 11+.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Could not exclude own package: ${e.message}")
        }

        try {
            vpnInterface = builder.establish()
                ?: throw IllegalStateException(
                    "VPN establish() returned null — " +
                            "check that VPN permission was granted and no Always-On VPN is active"
                )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            broadcastSaveResult(false, "Failed to start VPN: ${e.message}")
            return
        }

        isRunning = true

        // Android 14+ requires the foreground service type in startForeground()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification("Capturing traffic..."),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification("Capturing traffic..."))
        }

        startCaptureLoop()
        startExpireLoop()
        startStatsLoop()
    }

    private fun startCaptureLoop() {
        val pfd = vpnInterface ?: return

        captureJob = serviceScope.launch {
            Log.i(TAG, "Capture loop starting")

            // ── KEY FIX ────────────────────────────────────────────────────────
            // On Android 11+, FileInputStream.read() on a VPN file descriptor
            // blocks forever and never delivers data because the TUN fd's blocking
            // behavior changed. We must use FileChannel (NIO) with a direct
            // ByteBuffer instead — this works correctly on all API levels 9–16+.
            //
            // Additionally, we do NOT write packets back to the fd. On Android 9/10
            // this was a no-op. On Android 15/16 it interferes with the VPN stack
            // and can stall the read loop. The OS routes traffic independently;
            // our job is only to read and parse, not to re-inject.
            // ──────────────────────────────────────────────────────────────────

            val fileChannel: FileChannel = FileInputStream(pfd.fileDescriptor).channel
            val packetBuffer: ByteBuffer = ByteBuffer.allocateDirect(MTU)

            Log.i(TAG, "FileChannel opened, entering read loop")

            while (isActive) {
                try {
                    packetBuffer.clear()

                    // FileChannel.read() on a TUN fd works correctly on all
                    // Android versions. It returns -1 if the tunnel is closed,
                    // 0 if no packet is available (non-blocking mode), or the
                    // packet length if a packet was read.
                    val length = fileChannel.read(packetBuffer)

                    when {
                        length < 0 -> {
                            // Tunnel was closed externally
                            Log.w(TAG, "TUN fd closed (read returned -1), stopping capture loop")
                            break
                        }
                        length == 0 -> {
                            // No packet available right now — yield briefly to avoid
                            // a busy-spin that would drain the battery
                            delay(1)
                            continue
                        }
                        else -> {
                            val nowMs = System.currentTimeMillis()
                            totalPackets++
                            totalBytes += length

                            // Flip so we can read from position 0 to limit=length
                            packetBuffer.flip()
                            val rawBytes = ByteArray(length)
                            packetBuffer.get(rawBytes)

                            PacketParser.parse(rawBytes, length)?.let { packet ->
                                flowTracker.processPacket(packet, nowMs)
                            }
                        }
                    }
                } catch (e: Exception) {
                    if (isActive) {
                        Log.w(TAG, "Packet read error: ${e.javaClass.simpleName}: ${e.message}")
                        // Brief pause before retrying to avoid a tight error loop
                        delay(5)
                    }
                }
            }

            Log.i(TAG, "Capture loop ended. Total packets: $totalPackets")

            try { fileChannel.close() } catch (_: Exception) {}
        }
    }

    private fun startExpireLoop() {
        expireJob = serviceScope.launch {
            while (isActive) {
                delay(EXPIRE_INTERVAL_MS)
                flowTracker.expireFlows(System.currentTimeMillis())
                Log.d(TAG, "Flows — active: ${flowTracker.getActiveFlowCount()}, " +
                        "completed: ${flowTracker.getCompletedFlowCount()}")
            }
        }
    }

    private fun startStatsLoop() {
        statsJob = serviceScope.launch {
            while (isActive) {
                delay(2000)
                broadcastStats()
                updateNotification()
            }
        }
    }

    fun stopCapture(autoSave: Boolean = false) {
        if (!isRunning) return
        Log.i(TAG, "Stopping traffic capture")

        isRunning = false
        captureJob?.cancel()
        expireJob?.cancel()
        statsJob?.cancel()

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.w(TAG, "Error closing VPN interface: ${e.message}")
        }

        if (autoSave) saveFlows()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        broadcastStats()
    }

    fun saveFlows() {
        serviceScope.launch {
            val flows = flowTracker.finalizeAll()
            if (flows.isEmpty()) {
                broadcastSaveResult(false, "No flows collected yet.")
                return@launch
            }
            try {
                // Classify each flow using the rule-based heuristic classifier.
                // NOTE: classification order matters for cross-flow detection
                // (port scan / host discovery / SYN flood patterns) — flows
                // must be classified in chronological order so the sliding
                // window sees activity in the order it actually happened.
                val sortedFlows = flows.sortedBy { it.startTimeMs }
                val verdicts: Map<String, TrafficVerdict> = sortedFlows.associate { flow ->
                    flow.flowId to classifier.classify(flow)
                }

                val fileName = ExcelExporter.export(this@TrafficCaptureService, sortedFlows, verdicts)
                Log.i(TAG, "Exported ${flows.size} flows to $fileName")
                broadcastSaveResult(true, "Saved ${flows.size} flows → Downloads/$fileName")
            } catch (e: Exception) {
                Log.e(TAG, "Export failed", e)
                broadcastSaveResult(false, "Export failed: ${e.message}")
            } finally {
                // Reset classifier state so the next session starts clean —
                // otherwise stale sliding-window data from this session could
                // bleed into the next one.
                classifier.reset()
            }
        }
    }

    // ── Notification ───────────────────────────────────────────────────────────

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Network Capture",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows while network traffic is being captured"
            }
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        ensureNotificationChannel()

        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, TrafficCaptureService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val saveIntent = PendingIntent.getService(
            this, 1,
            Intent(this, TrafficCaptureService::class.java).apply { action = ACTION_SAVE },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(
                this, 2, it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NetCapture Active")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_capture_notification)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(0, "Stop & Save", stopIntent)
            .addAction(0, "Save Now", saveIntent)
            .build()
    }

    private fun updateNotification() {
        if (!isRunning) return
        val text = "Flows: ${flowTracker.getTotalFlowCount()} | " +
                "Pkts: $totalPackets | ${formatBytes(totalBytes)}"
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    // ── Broadcasts ─────────────────────────────────────────────────────────────

    private fun broadcastStats() {
        sendBroadcast(Intent(BROADCAST_STATS).apply {
            `package` = packageName          // ← ADD THIS LINE
            putExtra(EXTRA_TOTAL_FLOWS, flowTracker.getTotalFlowCount())
            putExtra(EXTRA_TOTAL_PACKETS, totalPackets)
            putExtra(EXTRA_TOTAL_BYTES, totalBytes)
            putExtra(EXTRA_IS_RUNNING, isRunning)
        })
    }

    private fun broadcastSaveResult(success: Boolean, message: String) {
        sendBroadcast(Intent(BROADCAST_SAVE_RESULT).apply {
            `package` = packageName          // ← ADD THIS LINE
            putExtra(EXTRA_SAVE_SUCCESS, success)
            putExtra(EXTRA_SAVE_MESSAGE, message)
        })
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "${bytes}B"
        bytes < 1048576 -> "${"%.1f".format(bytes / 1024.0)}KB"
        else -> "${"%.1f".format(bytes / 1048576.0)}MB"
    }
}
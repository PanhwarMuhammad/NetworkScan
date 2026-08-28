package com.muhammad.networkscan.classifier

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
import com.muhammad.networkscan.R
import com.muhammad.networkscan.classifier.FlowTracker
import com.muhammad.networkscan.models.PacketParser
import com.muhammad.networkscan.models.ParsedPacket
import com.muhammad.networkscan.room.CaptureRepository
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap


// What you CAN measure via this approach:
//   All UDP flows (DNS, QUIC/HTTP3, streaming, games)
//  All TCP flows (HTTP, HTTPS, any TCP app)
//    Packet counts, byte counts, IAT, flags, port numbers
//   TLS SNI (from ClientHello, before encryption)
//   Flow duration, rates, all DT features
class NetworkCaptureService : VpnService() {

    companion object {
        private const val TAG = "NIDS_DIAG"
        private const val CHANNEL_ID = "nids_capture_channel"
        private const val NOTIFICATION_ID = 9001
        const val ACTION_START = "com.muhammad.networkscan.START_CAPTURE"
        const val ACTION_STOP = "com.muhammad.networkscan.STOP_CAPTURE"
        private const val MTU = 32767

    }

    inner class LocalBinder : Binder() {
        fun getService(): NetworkCaptureService = this@NetworkCaptureService
    }
    private val localBinder = LocalBinder()
    override fun onBind(intent: Intent?): IBinder = localBinder

    @Volatile var packetsProcessed = 0L
    @Volatile var flowsCompleted   = 0L
    @Volatile var bytesProcessed   = 0L
    @Volatile var isRunning        = false
        private set

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunFd: ParcelFileDescriptor? = null
    private lateinit var repo: CaptureRepository
    private lateinit var tracker: FlowTracker


    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "=== SERVICE onCreate ===")
        repo = CaptureRepository(this)
        tracker = FlowTracker(
            onFlowComplete = { record ->
                scope.launch {
                    repo.save(record)
                    flowsCompleted++
                    Log.d(TAG, "Flow saved: ${record.protocolName} " +
                            "${record.srcIp}:${record.srcPort} → ${record.dstIp}:${record.dstPort} " +
                            "pkts=${record.totalPackets} bytes=${record.totalLengthFwdPackets + record.totalLengthBwdPackets}")
                }
            },
            idleTimeoutUs = 30_000_000L,
            maxFlows = 256
        )
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "=== onStartCommand action=${intent?.action} ===")
        when (intent?.action) {
            ACTION_STOP -> { stopCapture(); return START_NOT_STICKY }
            else        -> if (!isRunning) startCapture()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        Log.d(TAG, "=== SERVICE onDestroy ===")
        stopCapture()
        scope.cancel()
        super.onDestroy()
    }


    private fun startCapture() {
        Log.d(TAG, "startCapture() called")
        isRunning = true

        // Step 1: Build VPN interface
        Log.d(TAG, "STEP 1: Calling VpnService.Builder.establish()...")
        val pfd = buildVpnInterface()
        if (pfd == null) {
            Log.e(TAG, "STEP 1 FAILED: VPN interface returned null — did user grant VPN permission?")
            isRunning = false
            stopSelf()
            return
        }
        Log.d(TAG, "STEP 1 OK: VPN interface established. fd=${pfd.fd}")
        tunFd = pfd

        startForeground(NOTIFICATION_ID, buildNotification())
        Log.d(TAG, "STEP 2: Foreground started")

        // Step 3: Start read loop
        Log.d(TAG, "STEP 3: Launching readLoop coroutine...")
        scope.launch { readLoop(pfd) }

        // Step 4: Idle eviction
        scope.launch {
            while (isRunning) {
                delay(15_000)
                tracker.evictIdle(System.nanoTime() / 1000)
                Log.d(TAG, "Idle eviction tick — packets=$packetsProcessed flows=$flowsCompleted bytes=$bytesProcessed")
            }
        }
    }

    private fun stopCapture() {
        if (!isRunning) return
        isRunning = false
        Log.d(TAG, "stopCapture() — final: packets=$packetsProcessed flows=$flowsCompleted bytes=$bytesProcessed")
        tracker.flushAll()
        try { tunFd?.close() } catch (_: IOException) {}
        tunFd = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }




    private fun buildVpnInterface(): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
                .setSession("NIDS Diagnostic")
                .setMtu(MTU)
                .addAddress("10.215.173.1", 32)
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0)
                .allowFamily(android.system.OsConstants.AF_INET)

            try {
                builder.allowFamily(android.system.OsConstants.AF_INET6)
                Log.d(TAG, "IPv6 passthrough allowed")
            } catch (e: Exception) {
                Log.w(TAG, "IPv6 passthrough not supported: ${e.message}")
            }

            val pfd = builder.establish()
            Log.d(TAG, "establish() returned: $pfd")
            pfd
        } catch (e: Exception) {
            Log.e(TAG, "buildVpnInterface EXCEPTION: ${e.javaClass.simpleName}: ${e.message}", e)
            null
        }
    }



    private suspend fun readLoop(pfd: ParcelFileDescriptor) {
        Log.d(TAG, "readLoop() STARTED on thread=${Thread.currentThread().name}")
        val input = FileInputStream(pfd.fileDescriptor)
        val buf   = ByteArray(MTU)
        var readAttempts  = 0
        var emptyReads    = 0
        var parseFailures = 0

        while (isRunning) {
            try {
                val len = withContext(Dispatchers.IO) { input.read(buf) }
                readAttempts++

                if (readAttempts <= 5) {
                    Log.d(TAG, "read() #$readAttempts returned len=$len")
                }

                if (len <= 0) {
                    emptyReads++
                    if (emptyReads % 100 == 1) {
                        Log.w(TAG, "Empty/EOF read #$emptyReads — TUN may be closed or no traffic")
                    }
                    delay(5)
                    continue
                }

                packetsProcessed++
                bytesProcessed += len

                if (packetsProcessed <= 20 || packetsProcessed % 100 == 0L) {
                    val ipVer  = (buf[0].toInt() and 0xFF) ushr 4
                    val proto  = if (len >= 10) buf[9].toInt() and 0xFF else -1
                    val protoName = when (proto) { 6 -> "TCP"; 17 -> "UDP"; 1 -> "ICMP"; else -> "other($proto)" }
                    Log.d(TAG, "PKT #$packetsProcessed len=$len ipVer=$ipVer proto=$protoName " +
                            "first4bytes=${buf[0].toHex()}${buf[1].toHex()}${buf[2].toHex()}${buf[3].toHex()}")
                }

                val nowUs  = System.nanoTime() / 1000
                val parsed = PacketParser.parse(buf, len, nowUs)
                if (parsed == null) {
                    parseFailures++
                    if (parseFailures <= 5) {
                        Log.w(TAG, "PacketParser returned null for len=$len, first byte=${buf[0].toHex()}")
                    }
                } else {
                    tracker.feed(parsed)
                }

            } catch (e: IOException) {
                Log.e(TAG, "readLoop IOException: ${e.message} — TUN fd may have closed")
                if (isRunning) delay(100) else break
            } catch (e: Exception) {
                Log.e(TAG, "readLoop Exception: ${e.javaClass.simpleName}: ${e.message}", e)
            }
        }

        Log.d(TAG, "readLoop() EXITED — total: attempts=$readAttempts empty=$emptyReads " +
                "packets=$packetsProcessed parseFails=$parseFailures")
    }

    private fun Byte.toHex() = "%02X".format(this)


    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_ID, "NIDS Capture",
                NotificationManager.IMPORTANCE_LOW
            ).apply { setShowBadge(false) }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(): Notification {
        val stopPi = PendingIntent.getService(
            this, 0,
            Intent(this, NetworkCaptureService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return androidx.core.app.NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NIDS Diagnostic Running")
            .setContentText("Check Logcat for NIDS_DIAG tag")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
            .addAction(android.R.drawable.ic_delete, "Stop", stopPi)
            .build()
    }
}

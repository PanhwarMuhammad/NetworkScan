package com.muhammad.networkscan.viewmodels

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.lifecycle.*
import com.muhammad.networkscan.classifier.NetworkCaptureService
import com.muhammad.networkscan.models.FlowRecord
import com.muhammad.networkscan.room.CaptureRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.*


data class CaptureFilter(
    val protocol: String? = null,      // null = all
    val flaggedOnly: Boolean = false,
    val limit: Int = 200
)

data class CaptureStats(
    val totalFlows: Int    = 0,
    val flaggedFlows: Int  = 0,
    val packetsRead: Long  = 0L,
    val bytesRead: Long    = 0L,
    val isCapturing: Boolean = false
)

class CaptureViewModel(app: Application) : AndroidViewModel(app) {

    private val repo =
        CaptureRepository(app)

    private val _filter = MutableStateFlow(CaptureFilter())
    val filter: StateFlow<CaptureFilter> = _filter

    val records: StateFlow<List<FlowRecord>> = _filter
        .flatMapLatest { f ->
            repo.filtered(f.protocol, f.flaggedOnly, f.limit)
        }
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    private val _stats = MutableStateFlow(CaptureStats())
    val stats: StateFlow<CaptureStats> = _stats

    private val _message = MutableSharedFlow<String>()
    val message: SharedFlow<String> = _message

    private var captureService: NetworkCaptureService? = null

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            captureService = (binder as? NetworkCaptureService.LocalBinder)?.getService()
            startStatsPolling()
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            captureService = null
        }
    }

    fun bindService(context: Context) {
        val intent = Intent(context, NetworkCaptureService::class.java)
        context.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    fun unbindService(context: Context) {
        try { context.unbindService(serviceConnection) } catch (_: Exception) {}
        captureService = null
    }

    private fun startStatsPolling() {
        viewModelScope.launch {
            repo.totalCount().combine(repo.flaggedCount()) { total, flagged ->
                total to flagged
            }.collect { (total, flagged) ->
                val svc = captureService
                _stats.value = CaptureStats(
                    totalFlows   = total,
                    flaggedFlows = flagged,
                    packetsRead  = svc?.packetsProcessed ?: 0L,
                    bytesRead    = svc?.bytesProcessed   ?: 0L,
                    isCapturing  = svc != null
                )
            }
        }
    }


    fun setProtocolFilter(proto: String?) {
        _filter.value = _filter.value.copy(protocol = proto)
    }

    fun setFlaggedOnly(flaggedOnly: Boolean) {
        _filter.value = _filter.value.copy(flaggedOnly = flaggedOnly)
    }

    fun clearFilters() {
        _filter.value = CaptureFilter()
    }


    fun deleteAll() = viewModelScope.launch {
        repo.deleteAll()
        _message.emit("All records deleted")
    }

    fun deleteById(id: Long) = viewModelScope.launch {
        repo.deleteById(id)
    }

    fun pruneOldRecords(days: Int = 7) = viewModelScope.launch {
        val count = repo.pruneOlderThan(days)
        _message.emit("Deleted $count records older than $days days")
    }

    fun exportCsv(context: Context) = viewModelScope.launch(Dispatchers.IO) {
        try {
            val csv  = repo.exportCsv()
            val date = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val file = File(context.getExternalFilesDir(null), "nids_capture_$date.csv")
            file.writeText(csv)
            _message.emit("Exported to: ${file.absolutePath}")
        } catch (e: Exception) {
            _message.emit("Export failed: ${e.message}")
        }
    }


    private val _selectedRecord = MutableStateFlow<FlowRecord?>(null)
    val selectedRecord: StateFlow<FlowRecord?> = _selectedRecord

    fun selectRecord(id: Long) = viewModelScope.launch {
        _selectedRecord.value = repo.getById(id)
    }

    fun clearSelection() { _selectedRecord.value = null }
}

class CaptureViewModelFactory(private val app: Application)
    : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        @Suppress("UNCHECKED_CAST")
        return CaptureViewModel(app) as T
    }
}
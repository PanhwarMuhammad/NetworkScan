package com.muhammad.networkscan.room


import android.content.Context
import androidx.room.*
import com.muhammad.networkscan.models.CSV_HEADER
import com.muhammad.networkscan.models.FlowRecord
import com.muhammad.networkscan.models.FlowRecordConverters
import com.muhammad.networkscan.models.toCsvRow
import kotlinx.coroutines.flow.Flow

// ─────────────────────────────────────────────────────────────────────────────
// CaptureDatabase.kt
//
// Room database for persisting FlowRecord objects.
// Three files in one for convenience:
//   • FlowRecordDao  – queries
//   • CaptureDatabase – Room singleton
//   • CaptureRepository – coroutine-friendly data layer
// ─────────────────────────────────────────────────────────────────────────────

// ── DAO ───────────────────────────────────────────────────────────────────────

@Dao
interface FlowRecordDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(record: FlowRecord): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(records: List<FlowRecord>)

    @Query("SELECT * FROM flow_records ORDER BY captureTimestamp DESC LIMIT :limit OFFSET :offset")
    fun getPagedRecords(limit: Int, offset: Int): Flow<List<FlowRecord>>

    @Query("SELECT * FROM flow_records ORDER BY captureTimestamp DESC")
    fun getAllRecords(): Flow<List<FlowRecord>>

    @Query("SELECT * FROM flow_records WHERE id = :id")
    suspend fun getById(id: Long): FlowRecord?

    @Query("SELECT * FROM flow_records WHERE isFlagged = 1 ORDER BY captureTimestamp DESC")
    fun getFlaggedRecords(): Flow<List<FlowRecord>>

    @Query("SELECT * FROM flow_records WHERE protocolName = :proto ORDER BY captureTimestamp DESC")
    fun getByProtocol(proto: String): Flow<List<FlowRecord>>

    @Query("SELECT COUNT(*) FROM flow_records")
    fun getTotalCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM flow_records WHERE isFlagged = 1")
    fun getFlaggedCount(): Flow<Int>

    @Query("SELECT DISTINCT predictedLabel FROM flow_records")
    suspend fun getDistinctLabels(): List<String>

    @Query("""
        SELECT * FROM flow_records 
        WHERE (:proto IS NULL OR protocolName = :proto)
        AND (:flagged = 0 OR isFlagged = 1)
        ORDER BY captureTimestamp DESC
        LIMIT :limit
    """)
    fun getFiltered(proto: String?, flagged: Int, limit: Int): Flow<List<FlowRecord>>

    @Query("DELETE FROM flow_records")
    suspend fun deleteAll()

    @Query("DELETE FROM flow_records WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM flow_records WHERE captureTimestamp < :beforeMs")
    suspend fun deleteOlderThan(beforeMs: Long): Int

    // Summary stats for dashboard
    @Query("SELECT AVG(flowBytesPerSec) FROM flow_records")
    suspend fun avgBytesPerSec(): Double?

    @Query("SELECT AVG(totalPackets) FROM flow_records")
    suspend fun avgTotalPackets(): Double?
}

// ── Database ──────────────────────────────────────────────────────────────────

@Database(
    entities = [FlowRecord::class],
    version  = 1,
    exportSchema = false
)
@TypeConverters(FlowRecordConverters::class)
abstract class CaptureDatabase : RoomDatabase() {

    abstract fun flowRecordDao(): FlowRecordDao

    companion object {
        @Volatile private var INSTANCE: CaptureDatabase? = null

        fun getInstance(context: Context): CaptureDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    CaptureDatabase::class.java,
                    "nids_capture.db"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                    .also { INSTANCE = it }
            }
    }
}

// ── Repository ────────────────────────────────────────────────────────────────

class CaptureRepository(context: Context) {

    private val dao = CaptureDatabase.getInstance(context).flowRecordDao()

    suspend fun save(record: FlowRecord) { dao.insert(record) }
    suspend fun saveAll(records: List<FlowRecord>) { dao.insertAll(records) }

    fun allRecords(): Flow<List<FlowRecord>>  = dao.getAllRecords()
    fun flaggedRecords(): Flow<List<FlowRecord>> = dao.getFlaggedRecords()
    fun totalCount(): Flow<Int>               = dao.getTotalCount()
    fun flaggedCount(): Flow<Int>             = dao.getFlaggedCount()

    fun filtered(proto: String?, flaggedOnly: Boolean, limit: Int = 200): Flow<List<FlowRecord>> =
        dao.getFiltered(proto, if (flaggedOnly) 1 else 0, limit)

    suspend fun getById(id: Long): FlowRecord? = dao.getById(id)
    suspend fun deleteAll()                     = dao.deleteAll()
    suspend fun deleteById(id: Long)            = dao.deleteById(id)

    /** Remove records older than [days] days. Returns count deleted. */
    suspend fun pruneOlderThan(days: Int): Int {
        val cutoffMs = System.currentTimeMillis() - days * 86_400_000L
        return dao.deleteOlderThan(cutoffMs)
    }

    suspend fun getDistinctLabels(): List<String> = dao.getDistinctLabels()

    /** Export all records as a CSV string (including header row). */
    suspend fun exportCsv(): String {
        val sb = StringBuilder()
        sb.appendLine(CSV_HEADER)
        dao.getAllRecords().collect { records ->
            records.forEach { sb.appendLine(it.toCsvRow()) }
        }
        return sb.toString()
    }
}
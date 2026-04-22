package com.muhammad.networkscan

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.viewpager2.widget.ViewPager2
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    // ── Views ─────────────────────────────────────────────────────────────────
    private lateinit var btnImport     : Button
    private lateinit var progressBar   : ProgressBar
    private lateinit var txtSummary    : TextView
    private lateinit var viewPager     : ViewPager2
    private lateinit var btnPrev       : Button
    private lateinit var btnNext       : Button
    private lateinit var txtPageCounter: TextView

    // ── Adapter ───────────────────────────────────────────────────────────────
    private lateinit var adapter: RecordAdapter

    private val PICK_CSV_FILE = 100

    // Single background thread for CSV reading + 5-second delays
    private val executor = Executors.newSingleThreadExecutor()

    @Volatile private var isProcessing = false

    // Only class that is non-malicious
    private val BENIGN_CLASS = "BenignTraffic"

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnImport      = findViewById(R.id.btnImportCsv)
        progressBar    = findViewById(R.id.progressBar)
        txtSummary     = findViewById(R.id.txtSummary)
        viewPager      = findViewById(R.id.viewPager)
        btnPrev        = findViewById(R.id.btnPrev)
        btnNext        = findViewById(R.id.btnNext)
        txtPageCounter = findViewById(R.id.txtPageCounter)

        // Set up adapter
        adapter = RecordAdapter()
        viewPager.adapter = adapter

        // Disable swipe gestures — navigation is arrow-only
        viewPager.isUserInputEnabled = false

        // ── Arrow buttons ─────────────────────────────────────────────────────
        btnPrev.setOnClickListener {
            val target = viewPager.currentItem - 1
            if (target >= 0) viewPager.setCurrentItem(target, true)
        }

        btnNext.setOnClickListener {
            val target = viewPager.currentItem + 1
            if (target < adapter.itemCount) viewPager.setCurrentItem(target, true)
        }

        // Update arrow enabled state and counter whenever the page changes
        viewPager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                updateNavBar(position)
            }
        })

        btnImport.setOnClickListener { openFilePicker() }
    }

    // ── Navigation bar ────────────────────────────────────────────────────────

    private fun updateNavBar(position: Int) {
        val total = adapter.itemCount
        btnPrev.isEnabled       = position > 0
        btnNext.isEnabled       = position < total - 1
        txtPageCounter.text     = if (total == 0) "—" else "${position + 1} / $total"
    }

    // ── File picker ───────────────────────────────────────────────────────────

    private fun openFilePicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "text/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        startActivityForResult(intent, PICK_CSV_FILE)
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PICK_CSV_FILE && resultCode == Activity.RESULT_OK) {
            data?.data?.let { startProcessing(it) }
        }
    }

    // ── Start processing ──────────────────────────────────────────────────────

    private fun startProcessing(uri: Uri) {
        // Reset adapter for new session
        adapter = RecordAdapter()
        viewPager.adapter = adapter
        updateNavBar(0)

        isProcessing           = true
        btnImport.isEnabled    = false
        progressBar.visibility = View.VISIBLE
        txtSummary.text        = "Loading…"
        txtPageCounter.text    = "—"

        executor.execute {
            try {
                val stream = contentResolver.openInputStream(uri)
                    ?: throw Exception("Cannot open file")
                processRecords(BufferedReader(InputStreamReader(stream)))
            } catch (e: Exception) {
                runOnUiThread {
                    txtSummary.text = "Error: ${e.message}"
                    resetUI()
                }
            }
        }
    }

    // ── Core loop ─────────────────────────────────────────────────────────────

    private fun processRecords(reader: BufferedReader) {

        // 1. Parse header
        val headerLine = reader.readLine() ?: run {
            runOnUiThread { txtSummary.text = "Error: empty file"; resetUI() }
            return
        }
        val headers = headerLine.split(",").map { it.trim() }
        fun idx(name: String) = headers.indexOf(name).also { i ->
            if (i == -1) throw Exception("Column '$name' not found")
        }

        val iFlowDuration  = idx("flow_duration")
        val iHeaderLength  = idx("Header_Length")
        val iProtocolType  = idx("Protocol Type")
        val iDuration      = idx("Duration")
        val iRate          = idx("Rate")
        val iSrate         = idx("Srate")
        val iFinFlagNumber = idx("fin_flag_number")
        val iSynFlagNumber = idx("syn_flag_number")
        val iPshFlagNumber = idx("psh_flag_number")
        val iAckCount      = idx("ack_count")
        val iSynCount      = idx("syn_count")
        val iFinCount      = idx("fin_count")
        val iUrgCount      = idx("urg_count")
        val iRstCount      = idx("rst_count")
        val iHTTP          = idx("HTTP")
        val iHTTPS         = idx("HTTPS")
        val iUDP           = idx("UDP")
        val iICMP          = idx("ICMP")
        val iTotSum        = idx("Tot sum")
        val iMin           = idx("Min")
        val iMax           = idx("Max")
        val iStd           = idx("Std")
        val iTotSize       = idx("Tot size")
        val iIAT           = idx("IAT")
        val iNumber        = idx("Number")
        // *** Column in CSV is "Magnitue" (original typo) → field: magnitude ***
        val iMagnitue      = idx("Magnitue")
        val iRadius        = idx("Radius")
        val iCovariance    = idx("Covariance")
        val iVariance      = idx("Variance")
        val iWeight        = idx("Weight")
        val iLabel         = headers.indexOf("label")   // -1 if absent

        // 2. Row-by-row loop
        var rowNum    = 0
        var correct   = 0
        var wrong     = 0
        var truncated = 0

        var line: String?
        while (reader.readLine().also { line = it } != null && isProcessing) {
            val raw = line!!
            if (raw.isBlank()) continue
            val cols = raw.split(",")
            if (cols.size < headers.size) continue

            rowNum++
            fun d(i: Int): Double = cols[i].trim().toDoubleOrNull() ?: 0.0

            val sample = NetworkTrafficClassifier.NetworkFlowSample(
                min           = d(iMin),
                max           = d(iMax),
                std           = d(iStd),
                variance      = d(iVariance),
                iat           = d(iIAT),
                totSum        = d(iTotSum),
                totSize       = d(iTotSize),
                headerLength  = d(iHeaderLength),
                number        = d(iNumber),
                rate          = d(iRate),
                srate         = d(iSrate),
                covariance    = d(iCovariance),
                magnitude     = d(iMagnitue),   // *** mapped from "Magnitue" ***
                radius        = d(iRadius),
                weight        = d(iWeight),
                duration      = d(iDuration),
                flowDuration  = d(iFlowDuration),
                protocolType  = d(iProtocolType),
                icmp          = d(iICMP),
                udp           = d(iUDP),
                http          = d(iHTTP),
                https         = d(iHTTPS),
                finFlagNumber = d(iFinFlagNumber),
                pshFlagNumber = d(iPshFlagNumber),
                synFlagNumber = d(iSynFlagNumber),
                finCount      = d(iFinCount),
                synCount      = d(iSynCount),
                rstCount      = d(iRstCount),
                ackCount      = d(iAckCount),
                urgCount      = d(iUrgCount)
            )

            val predicted   = NetworkTrafficClassifier.classify(sample)
            val actualLabel = if (iLabel != -1) cols[iLabel].trim() else null
            val isTruncated = predicted == NetworkTrafficClassifier.UNKNOWN_TRUNCATED

            // Resolve display name
            val attackType = when {
                !isTruncated        -> predicted
                actualLabel != null -> actualLabel
                else                -> "Unknown Attack"
            }

            // Verdict — truncated is always malicious
            val isMalicious = isTruncated || attackType != BENIGN_CLASS

            // Accuracy
            val isCorrect: Boolean? = when {
                actualLabel == null -> null
                isTruncated        -> null   // truncated = not a tree decision
                else               -> predicted == actualLabel
            }

            if (actualLabel != null) {
                when {
                    isTruncated            -> truncated++
                    isCorrect == true      -> correct++
                    else                   -> wrong++
                }
            }
            val classNumber = NetworkTrafficClassifier.classNumberFor(attackType)


            // Build the record and push to adapter on UI thread
            val record = RecordResult(
                rowNumber   = rowNum,
                attackType  = attackType,
                classNumber = classNumber,
                isMalicious = isMalicious,
                isTruncated = isTruncated,
                actualLabel = actualLabel,
                isCorrect   = isCorrect
            )

            val summaryText = if (iLabel != -1)
                "Processed: $rowNum   ✓ $correct   ✗ $wrong   ⚠ $truncated"
            else
                "Processed: $rowNum records"

            val capturedRow = rowNum  // capture for lambda

            runOnUiThread {
                adapter.addRecord(record)
                txtSummary.text = summaryText

                // Auto-advance to the new card while it's the latest one,
                // but only if the user hasn't manually navigated away
                val lastIdx = adapter.itemCount - 1
                if (viewPager.currentItem == lastIdx - 1 || lastIdx == 0) {
                    viewPager.setCurrentItem(lastIdx, capturedRow > 1)
                }
                updateNavBar(viewPager.currentItem)
            }

            // 5-second pause before next record
            Thread.sleep(5000)
        }

        // 3. Final summary — add a summary "card" by updating the tally bar
        reader.close()

        val finalSummary = if (iLabel != -1) {
            val pct = if (rowNum > 0) correct * 100.0 / rowNum else 0.0
            "Done: $rowNum records   ✓ $correct (${"%.1f".format(pct)}%)   ✗ $wrong   ⚠ $truncated"
        } else {
            "Done — $rowNum records processed."
        }

        runOnUiThread {
            txtSummary.text = finalSummary
            resetUI()
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun resetUI() {
        isProcessing           = false
        btnImport.isEnabled    = true
        progressBar.visibility = View.GONE
    }

    override fun onDestroy() {
        super.onDestroy()
        isProcessing = false
        executor.shutdown()
    }
}
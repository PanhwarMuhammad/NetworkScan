package com.muhammad.networkscan.util


import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.muhammad.networkscan.live_traffic.TrafficCategory
import com.muhammad.networkscan.live_traffic.TrafficVerdict
import com.muhammad.networkscan.models.NetworkFlow
import org.apache.poi.ss.usermodel.BorderStyle
import org.apache.poi.ss.usermodel.FillPatternType
import org.apache.poi.ss.usermodel.HorizontalAlignment
import org.apache.poi.ss.usermodel.IndexedColors
import org.apache.poi.xssf.usermodel.XSSFWorkbook
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale



object ExcelExporter {

    private val dateFormatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    private val fileNameFormatter = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)

    /**
     * Exports the list of flows to an Excel file in the Downloads folder.
     * [verdicts] maps flowId -> classification result. Pass an empty map if
     * classification was not run (the Category/Confidence/Reason columns
     * will show "N/A").
     * Returns the file name on success, or throws on failure.
     */
    fun export(
        context: Context,
        flows: List<NetworkFlow>,
        verdicts: Map<String, TrafficVerdict> = emptyMap()
    ): String {
        val timestamp = fileNameFormatter.format(Date())
        val fileName = "NetworkScan_$timestamp.xlsx"

        val workbook = XSSFWorkbook()

        // ── Styles ─────────────────────────────────────────────────────────────
        val headerFont = workbook.createFont().apply {
            bold = true
            color = IndexedColors.WHITE.index
            fontHeightInPoints = 10
        }
        val headerStyle = workbook.createCellStyle().apply {
            setFont(headerFont)
            fillForegroundColor = IndexedColors.DARK_BLUE.index
            fillPattern = FillPatternType.SOLID_FOREGROUND
            alignment = HorizontalAlignment.CENTER
            setBorderBottom(BorderStyle.THIN)
            setBorderTop(BorderStyle.THIN)
            setBorderLeft(BorderStyle.THIN)
            setBorderRight(BorderStyle.THIN)
        }

        val altRowStyle = workbook.createCellStyle().apply {
            fillForegroundColor = IndexedColors.WHITE.index
            fillPattern = FillPatternType.SOLID_FOREGROUND
        }

        val normalStyle = workbook.createCellStyle()

        // Highlight style for rows flagged as non-benign by the classifier
        val flaggedStyle = workbook.createCellStyle().apply {
            fillForegroundColor = IndexedColors.LIGHT_ORANGE.index
            fillPattern = FillPatternType.SOLID_FOREGROUND
        }

        // ── Sheet 1: Flow Records ──────────────────────────────────────────────
        val flowSheet = workbook.createSheet("Flow Records")

        val headers = listOf(
            "Flow ID", "Protocol",
            "Source IP", "Source Port",
            "Destination IP", "Destination Port",
            "Start Time", "End Time", "Duration (ms)",
            "Fwd Packets", "Fwd Bytes",
            "Bwd Packets", "Bwd Bytes",
            "Total Packets", "Total Bytes",
            "Min Pkt Length", "Max Pkt Length", "Avg Pkt Length",
            "Bytes/Second", "Packets/Second",
            "TCP Flags (hex)",
            "FIN Count", "SYN Count", "RST Count",
            "PSH Count", "ACK Count", "URG Count",
            "Category", "Confidence", "Classification Reason"
        )

        // Header row
        val headerRow = flowSheet.createRow(0)
        headers.forEachIndexed { i, title ->
            val cell = headerRow.createCell(i)
            cell.setCellValue(title)
            cell.cellStyle = headerStyle
        }

        // Data rows
        flows.forEachIndexed { rowIdx, flow ->
            val row = flowSheet.createRow(rowIdx + 1)
            val verdict = verdicts[flow.flowId]
            val isFlagged = verdict != null && verdict.category != TrafficCategory.BENIGN
            val style = when {
                isFlagged -> flaggedStyle
                rowIdx % 2 == 0 -> normalStyle
                else -> normalStyle
            }

            fun cell(col: Int, value: String) =
                row.createCell(col).apply { setCellValue(value); cellStyle = style }
            fun cell(col: Int, value: Double) =
                row.createCell(col).apply { setCellValue(value); cellStyle = style }
            fun cell(col: Int, value: Long) =
                row.createCell(col).apply { setCellValue(value.toDouble()); cellStyle = style }

            cell(0, flow.flowId)
            cell(1, flow.protocol)
            cell(2, flow.srcIp)
            cell(3, flow.srcPort.toDouble())
            cell(4, flow.dstIp)
            cell(5, flow.dstPort.toDouble())
            cell(6, dateFormatter.format(Date(flow.startTimeMs)))
            cell(7, dateFormatter.format(Date(flow.lastSeenMs)))
            cell(8, flow.durationMs)
            cell(9, flow.fwdPackets)
            cell(10, flow.fwdBytes)
            cell(11, flow.bwdPackets)
            cell(12, flow.bwdBytes)
            cell(13, flow.totalPackets)
            cell(14, flow.totalBytes)
            cell(15, if (flow.minPacketLen == Int.MAX_VALUE) 0.0 else flow.minPacketLen.toDouble())
            cell(16, flow.maxPacketLen.toDouble())
            cell(17, flow.avgPacketLen)
            cell(18, flow.bytesPerSecond)
            cell(19, flow.packetsPerSecond)
            cell(20, "0x${flow.tcpFlags.toString(16).uppercase()}")
            cell(21, flow.finCount.toDouble())
            cell(22, flow.synCount.toDouble())
            cell(23, flow.rstCount.toDouble())
            cell(24, flow.pshCount.toDouble())
            cell(25, flow.ackCount.toDouble())
            cell(26, flow.urgCount.toDouble())
            cell(27, verdict?.category?.name ?: "N/A")
            cell(28, verdict?.confidence?.name ?: "N/A")
            cell(29, verdict?.reason ?: "Classification not run")
        }

        // Set fixed column widths manually. NOTE: We intentionally do NOT use
        // Sheet.autoSizeColumn() — it internally calls into java.awt.font.FontRenderContext
        // to measure text with a real font renderer, and java.awt does not exist
        // on Android (ART has no AWT implementation). Calling it crashes with
        // NoClassDefFoundError on a real device/emulator, even though it works
        // fine in a desktop JVM unit test. Width units are in 1/256 of a character.
        val flowColumnWidths = intArrayOf(
            12, 10,                          // Flow ID, Protocol
            16, 11,                          // Source IP, Source Port
            16, 14,                          // Destination IP, Destination Port
            24, 24, 13,                      // Start Time, End Time, Duration
            12, 11,                          // Fwd Packets, Fwd Bytes
            12, 11,                          // Bwd Packets, Bwd Bytes
            13, 12,                          // Total Packets, Total Bytes
            13, 13, 13,                      // Min/Max/Avg Pkt Length
            13, 14,                          // Bytes/Second, Packets/Second
            14,                               // TCP Flags
            9, 9, 9, 9, 9, 9,                 // FIN/SYN/RST/PSH/ACK/URG counts
            20, 12, 50                        // Category, Confidence, Classification Reason
        )
        flowColumnWidths.forEachIndexed { i, width ->
            flowSheet.setColumnWidth(i, width * 256)
        }

        // ── Sheet 2: Summary ───────────────────────────────────────────────────
        val summarySheet = workbook.createSheet("Summary")
        val summaryData = listOf(
            listOf("NetCapture Session Summary", ""),
            listOf("Export Time", dateFormatter.format(Date())),
            listOf("Total Flows", flows.size.toString()),
            listOf("TCP Flows", flows.count { it.protocol == "TCP" }.toString()),
            listOf("UDP Flows", flows.count { it.protocol == "UDP" }.toString()),
            listOf("ICMP Flows", flows.count { it.protocol == "ICMP" }.toString()),
            listOf("Other Flows", flows.count { it.protocol.startsWith("OTHER") }.toString()),
            listOf("Total Packets", flows.sumOf { it.totalPackets }.toString()),
            listOf("Total Bytes", flows.sumOf { it.totalBytes }.toString()),
            listOf("Unique Source IPs", flows.map { it.srcIp }.distinct().size.toString()),
            listOf("Unique Destination IPs", flows.map { it.dstIp }.distinct().size.toString()),
            listOf("Unique Destination Ports", flows.map { it.dstPort }.distinct().size.toString()),
            listOf("", ""),
            listOf("Classification Breakdown", ""),
        ) + TrafficCategory.values().map { category ->
            val count = verdicts.values.count { it.category == category }
            listOf(category.name, count.toString())
        }

        summaryData.forEachIndexed { i, (label, value) ->
            val row = summarySheet.createRow(i)
            row.createCell(0).setCellValue(label)
            row.createCell(1).setCellValue(value)
            if (i == 0 || label == "Classification Breakdown") {
                row.getCell(0).cellStyle = headerStyle
                row.getCell(1).cellStyle = headerStyle
            }
        }
        // Fixed widths — see note above about why autoSizeColumn is avoided on Android.
        summarySheet.setColumnWidth(0, 28 * 256)
        summarySheet.setColumnWidth(1, 16 * 256)

        // ── Sheet 3: Flagged Flows (only non-benign verdicts, for quick review) ─
        val flaggedFlows = flows.filter { verdicts[it.flowId]?.category != null &&
                verdicts[it.flowId]?.category != TrafficCategory.BENIGN }
        if (flaggedFlows.isNotEmpty()) {
            val flaggedSheet = workbook.createSheet("Flagged Flows")
            val flaggedHeaders = listOf(
                "Flow ID", "Protocol", "Source IP", "Destination IP", "Destination Port",
                "Start Time", "Category", "Confidence", "Reason"
            )
            val flaggedHeaderRow = flaggedSheet.createRow(0)
            flaggedHeaders.forEachIndexed { i, title ->
                flaggedHeaderRow.createCell(i).apply { setCellValue(title); cellStyle = headerStyle }
            }
            flaggedFlows.forEachIndexed { idx, flow ->
                val verdict = verdicts[flow.flowId]!!
                val row = flaggedSheet.createRow(idx + 1)
                val style = if (idx % 2 == 0) normalStyle else altRowStyle
                row.createCell(0).apply { setCellValue(flow.flowId); cellStyle = style }
                row.createCell(1).apply { setCellValue(flow.protocol); cellStyle = style }
                row.createCell(2).apply { setCellValue(flow.srcIp); cellStyle = style }
                row.createCell(3).apply { setCellValue(flow.dstIp); cellStyle = style }
                row.createCell(4).apply { setCellValue(flow.dstPort.toDouble()); cellStyle = style }
                row.createCell(5).apply { setCellValue(dateFormatter.format(Date(flow.startTimeMs))); cellStyle = style }
                row.createCell(6).apply { setCellValue(verdict.category.name); cellStyle = style }
                row.createCell(7).apply { setCellValue(verdict.confidence.name); cellStyle = style }
                row.createCell(8).apply { setCellValue(verdict.reason); cellStyle = style }
            }
            // Fixed widths — see note above about why autoSizeColumn is avoided on Android.
            val flaggedWidths = intArrayOf(12, 10, 16, 16, 14, 24, 20, 12, 60)
            flaggedWidths.forEachIndexed { i, width ->
                flaggedSheet.setColumnWidth(i, width * 256)
            }
        }

        // ── Write to Downloads ─────────────────────────────────────────────────
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Scoped storage (Android 10+)
            val resolver = context.contentResolver
            val contentValues = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, fileName)
                put(MediaStore.Downloads.MIME_TYPE,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                ?: throw IllegalStateException("Failed to create MediaStore entry")
            resolver.openOutputStream(uri)?.use { workbook.write(it) }
        } else {
            // Legacy storage (Android 9 and below)
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            downloadsDir.mkdirs()
            val file = File(downloadsDir, fileName)
            FileOutputStream(file).use { workbook.write(it) }
        }

        workbook.close()
        return fileName
    }
}
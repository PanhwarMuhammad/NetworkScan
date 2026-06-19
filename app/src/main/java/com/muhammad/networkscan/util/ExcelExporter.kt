package com.muhammad.networkscan.util


import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
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

    fun export(context: Context, flows: List<NetworkFlow>): String {
        val timestamp = fileNameFormatter.format(Date())
        val fileName = "NetworkScan_$timestamp.xlsx"

        val workbook = XSSFWorkbook()

        // ── Styles ──
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
            //fillForegroundColor = IndexedColors.LIGHT_CORNFLOWER_BLUE.index
            fillPattern = FillPatternType.SOLID_FOREGROUND
        }

        val normalStyle = workbook.createCellStyle()

        //Sheet 1: Flow Records
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
            "PSH Count", "ACK Count", "URG Count"
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
            val style = if (rowIdx % 2 == 0) normalStyle else altRowStyle

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
        }

        // Auto-size columns
        headers.indices.forEach { flowSheet.setColumnWidth(it, 20 * 256) }

        //  Sheet 2: Summary
        val summarySheet = workbook.createSheet("Summary")
        val summaryData = listOf(
            listOf("NetworkScan Session Summary", ""),
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
        )

        summaryData.forEachIndexed { i, (label, value) ->
            val row = summarySheet.createRow(i)
            row.createCell(0).setCellValue(label)
            row.createCell(1).setCellValue(value)
            if (i == 0) {
                row.getCell(0).cellStyle = headerStyle
                row.getCell(1).cellStyle = headerStyle
            }
        }
        summarySheet.setColumnWidth(0, 20 * 256)
        summarySheet.setColumnWidth(1, 20 * 256)

        // write to Downloads
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

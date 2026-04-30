package com.muhammad.networkscan.fragments

import android.os.Bundle
import android.view.LayoutInflater

import com.muhammad.networkscan.R

import android.app.AlertDialog
import android.app.Dialog
import android.view.View
import android.view.ViewGroup

import android.widget.Button
import android.widget.TextView
import androidx.fragment.app.DialogFragment
import com.muhammad.networkscan.models.RecordResult

class RecordDetails(private val record: RecordResult) : com.google.android.material.bottomsheet.BottomSheetDialogFragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_record_details, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val tvRow = view.findViewById<TextView>(R.id.tvRowNumber)
        val tvAttack = view.findViewById<TextView>(R.id.tvAttackType)
        val tvClass = view.findViewById<TextView>(R.id.tvClassNumber)
        val tvActual = view.findViewById<TextView>(R.id.tvActualLabel)
        val chipMalicious = view.findViewById<com.google.android.material.chip.Chip>(R.id.chipMalicious)
        val chipCorrect = view.findViewById<com.google.android.material.chip.Chip>(R.id.chipCorrect)
        val btnConfirm = view.findViewById<View>(R.id.btnConfirm)

        // Populate basic text
        tvRow.text = "#${record.rowNumber}"
        tvAttack.text = record.attackType
        tvClass.text = if (record.classNumber >= 0) record.classNumber.toString() else "Unknown"
        tvActual.text = record.actualLabel ?: "N/A"

        // Handle Malicious Chip
        if (record.isMalicious) {
            chipMalicious.text = "Malicious"
            chipMalicious.setChipBackgroundColorResource(android.R.color.holo_red_light)
        } else {
            chipMalicious.text = "Safe"
            chipMalicious.setChipBackgroundColorResource(android.R.color.holo_green_light)
        }

        when (record.isCorrect) {
            true -> {
                chipCorrect.visibility = View.VISIBLE
                chipCorrect.text = "Correct Match"
            }
            false -> {
                chipCorrect.visibility = View.VISIBLE
                chipCorrect.text = "Mismatched"
                chipCorrect.setChipBackgroundColorResource(android.R.color.darker_gray)
            }
            null -> chipCorrect.visibility = View.GONE
        }

        btnConfirm.setOnClickListener { dismiss() }
    }
}
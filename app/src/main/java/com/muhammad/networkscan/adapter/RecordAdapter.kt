package com.muhammad.networkscan

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.muhammad.networkscan.models.RecordResult


class RecordAdapter : RecyclerView.Adapter<RecordAdapter.RecordViewHolder>() {

    private val records = mutableListOf<RecordResult>()

    fun addRecord(record: RecordResult) {
        records.add(record)
        notifyItemInserted(records.size - 1)
    }
    fun getRecord(position: Int): RecordResult? {
        return records.getOrNull(position)
    }

    fun getCount(): Int = records.size

    override fun getItemCount(): Int = records.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecordViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_record_card, parent, false)
        return RecordViewHolder(view)
    }

    override fun onBindViewHolder(holder: RecordViewHolder, position: Int) {
        holder.bind(records[position])
    }


    class RecordViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

        private val cardRoot      : View     = itemView.findViewById(R.id.cardRoot)
        private val txtRecord     : TextView = itemView.findViewById(R.id.txtRecordNumber)
        private val txtVerdict    : TextView = itemView.findViewById(R.id.txtVerdict)
        private val txtClassNum   : TextView = itemView.findViewById(R.id.txtClassNumber)
        private val txtAttack     : TextView = itemView.findViewById(R.id.txtAttackType)
        private val txtTruncNote  : TextView = itemView.findViewById(R.id.txtTruncNote)
        private val txtActual     : TextView = itemView.findViewById(R.id.txtActualLabel)
        private val txtActualNum  : TextView = itemView.findViewById(R.id.txtActualClassNumber)
        private val txtMatch      : TextView = itemView.findViewById(R.id.txtMatch)

        fun bind(r: RecordResult) {

            txtRecord.text = "Record  #${r.rowNumber}"

            if (r.isMalicious) {
                txtVerdict.text = "MALICIOUS"
                txtVerdict.setTextColor(Color.parseColor("#C62828"))
                cardRoot.setBackgroundColor(Color.parseColor("#FFF3F3"))
            } else {
                txtVerdict.text = "NON-MALICIOUS"
                txtVerdict.setTextColor(Color.parseColor("#2E7D32"))
                cardRoot.setBackgroundColor(Color.parseColor("#F3FFF3"))
            }

            if (r.classNumber >= 0) {
                txtClassNum.visibility = View.VISIBLE
                txtClassNum.text       = "Class  #${r.classNumber}"
            } else {
                txtClassNum.visibility = View.GONE
            }

            txtAttack.text = r.attackType

            if (r.isTruncated) {
                txtTruncNote.visibility = View.GONE
                txtTruncNote.text       = "⚠  Rule branch truncated in rules file"
            } else {
                txtTruncNote.visibility = View.GONE
            }

            if (r.actualLabel != null) {
                txtActual.visibility    = View.GONE
                txtActualNum.visibility = View.GONE
                txtMatch.visibility     = View.VISIBLE

                txtActual.text = "Actual:  ${r.actualLabel}"

                val actualNum = NetworkTrafficClassifier.classNumberFor(r.actualLabel)
                txtActualNum.text = if (actualNum >= 0) "Actual Class  #$actualNum" else ""
                // txtActualNum.visibility = if (actualNum >= 0) View.VISIBLE else View.GONE

                val (matchText, matchColor) = when {
                    r.isTruncated       -> "⚠  Truncated (malicious)" to Color.parseColor("#E65100")
                    r.isCorrect == true -> "✓  Correct"               to Color.parseColor("#2E7D32")
                    else                -> "✗  Wrong"                  to Color.parseColor("#C62828")
                }
                txtMatch.text = matchText
                txtMatch.setTextColor(matchColor)
            } else {
                txtActual.visibility    = View.GONE
                txtActualNum.visibility = View.GONE
                txtMatch.visibility     = View.GONE
            }
        }
    }
}
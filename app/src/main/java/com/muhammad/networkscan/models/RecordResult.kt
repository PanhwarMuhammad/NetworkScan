package com.muhammad.networkscan.models

data class RecordResult(
    val rowNumber   : Int,
    val attackType  : String, // class name from tree, or actual label if truncated
    val classNumber : Int,      // 0-33 per rules file; -1 if unknown
    val isMalicious : Boolean,  // false only for BenignTraffic
    val isTruncated : Boolean,
    val actualLabel : String?,
    val isCorrect   : Boolean?
)

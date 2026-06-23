package com.muhammad.networkscan.models


data class LiveFlowUiModel(
    val flowId: String,
    val timeText: String,
    val src: String,
    val dst: String,
    val protocol: String,
    val category: String,
    val confidence: String,
    val reason: String,
    val isAlert: Boolean
)
package com.muhammad.networkscan.live_traffic


/**
 * Result of classifying a single flow.
 *
 * This is a HEURISTIC, RULE-BASED classification — not a trained ML model.
 * It is intentionally conservative: it flags only patterns with well-established
 * networking justification, and defaults to BENIGN/UNKNOWN when signals are weak.
 */
data class TrafficVerdict(
    val flowId: String,
    val category: TrafficCategory,
    val confidence: Confidence,
    val reason: String
)

enum class TrafficCategory {
    BENIGN,
    PORT_SCAN,
    HOST_DISCOVERY,
    SYN_FLOOD,
    GENERIC_FLOOD,
    BRUTE_FORCE_PATTERN,
    SUSPICIOUS_DNS,
    UNKNOWN
}

enum class Confidence {
    LOW,      // Pattern matches but could easily be benign (e.g. one-off retry)
    MEDIUM,   // Pattern is consistent with the category, some ambiguity remains
    HIGH      // Strong, repeated signal across multiple flows
}
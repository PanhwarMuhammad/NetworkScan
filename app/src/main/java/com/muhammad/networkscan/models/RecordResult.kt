package com.muhammad.networkscan

/**
 * Holds the classification result for one CSV row.
 * Passed into RecordAdapter and displayed as a paged card.
 */
data class RecordResult(
    val rowNumber   : Int,
    val attackType  : String, // class name from tree, or actual label if truncated
    val classNumber : Int,      // 0-33 per rules file; -1 if unknown
    val isMalicious : Boolean,  // false only for BenignTraffic
    val isTruncated : Boolean,  // true if tree hit a truncated branch
    val actualLabel : String?,  // null if CSV has no label column
    val isCorrect   : Boolean?  // null if no label; true/false otherwise (truncated = null)
)



/**
 * NetworkTrafficClassifier.kt
 *
 * A hand-translated decision tree classifier derived directly from
 * decision_tree_rules.txt. Every branch threshold and condition is
 * copied verbatim from that file — do NOT adjust any numeric constant
 * without re-checking the source file first.
 *
 * FEATURE NOTE — "Magnitue":
 *   The original rules file spells this feature "Magnitue" (missing the 'd').
 *   It is renamed here to [magnitude] for readability, but every threshold
 *   value and split condition is unchanged.
 *   *** SEARCH "magnitude" in your dataset mapping code and verify it maps
 *       to the column literally named "Magnitue" in the CSV. ***
 *
 * TRUNCATED BRANCHES:
 *   32 branches in the original file are marked "truncated branch of depth N".
 *   These sub-trees were cut off during export and their rules are unknown.
 *   Every such branch returns [UNKNOWN_TRUNCATED] so you can spot them
 *   at runtime and decide how to handle them (e.g. majority-class fallback).
 *
 * CLASS NUMBERS:
 *   [CLASS_NUMBER_MAP] maps every class name → its integer index (0-33)
 *   as listed in the "Class names:" section at the bottom of decision_tree_rules.txt.
 *   Use [classNumberFo] to look up the number for any predicted class name.
 */
object NetworkTrafficClassifie {

    // -------------------------------------------------------------------------
    // Return value for branches that were truncated in the exported rule file.
    // -------------------------------------------------------------------------
    const val UNKNOWN_TRUNCATED = "UNKNOWN_TRUNCATED"

    // -------------------------------------------------------------------------
    // Class number map — source: "Class names:" section in decision_tree_rules.txt
    // Integer key = class index used during sklearn training.
    // *** DO NOT reorder — these numbers come directly from the rules file. ***
    // -------------------------------------------------------------------------
    val CLASS_NUMBER_MAP: Map<String, Int> = mapOf(
        "Backdoor_Malware"        to 0,
        "BenignTraffic"           to 1,
        "BrowserHijacking"        to 2,
        "CommandInjection"        to 3,
        "DDoS-ACK_Fragmentation"  to 4,
        "DDoS-HTTP_Flood"         to 5,
        "DDoS-ICMP_Flood"         to 6,
        "DDoS-ICMP_Fragmentation" to 7,
        "DDoS-PSHACK_Flood"       to 8,
        "DDoS-RSTFINFlood"        to 9,
        "DDoS-SYN_Flood"          to 10,
        "DDoS-SlowLoris"          to 11,
        "DDoS-SynonymousIP_Flood" to 12,
        "DDoS-TCP_Flood"          to 13,
        "DDoS-UDP_Flood"          to 14,
        "DDoS-UDP_Fragmentation"  to 15,
        "DNS_Spoofing"            to 16,
        "DictionaryBruteForce"    to 17,
        "DoS-HTTP_Flood"          to 18,
        "DoS-SYN_Flood"           to 19,
        "DoS-TCP_Flood"           to 20,
        "DoS-UDP_Flood"           to 21,
        "MITM-ArpSpoofing"        to 22,
        "Mirai-greeth_flood"      to 23,
        "Mirai-greip_flood"       to 24,
        "Mirai-udpplain"          to 25,
        "Recon-HostDiscovery"     to 26,
        "Recon-OSScan"            to 27,
        "Recon-PingSweep"         to 28,
        "Recon-PortScan"          to 29,
        "SqlInjection"            to 30,
        "Uploading_Attack"        to 31,
        "VulnerabilityScan"       to 32,
        "XSS"                     to 33
    )

    /**
     * Returns the class number (0-33) for a given class name.
     * Returns -1 if the name is not in the map (e.g. UNKNOWN_TRUNCATED).
     */
    fun classNumberFor(className: String): Int =
        CLASS_NUMBER_MAP[className] ?: -1

    // -------------------------------------------------------------------------
    // Data class representing one network-flow row from your dataset.
    // Field names match dataset column names exactly, EXCEPT where noted.
    // -------------------------------------------------------------------------
    data class NetworkFlowSample(
        val min           : Double,    // "Min"
        val max           : Double,    // "Max"
        val std           : Double,    // "Std"
        val variance      : Double,    // "Variance"
        val iat           : Double,    // "IAT"
        val totSum        : Double,    // "Tot sum"
        val totSize       : Double,    // "Tot size"
        val headerLength  : Double,    // "Header_Length"
        val number        : Double,    // "Number"
        val rate          : Double,    // "Rate"
        val srate         : Double,    // "Srate"
        val covariance    : Double,    // "Covariance"

        // *** RENAMED: dataset column is "Magnitue" (typo) → mapped to [magnitude] here ***
        val magnitude     : Double,    // "Magnitue"  ← check your CSV column name!

        val radius        : Double,    // "Radius"
        val weight        : Double,    // "Weight"
        val duration      : Double,    // "Duration"
        val flowDuration  : Double,    // "flow_duration"
        val protocolType  : Double,    // "Protocol Type"

        // Protocol flags — stored as 0.0 or 1.0 in the dataset; split at 0.50
        val icmp          : Double,    // "ICMP"
        val udp           : Double,    // "UDP"
        val http          : Double,    // "HTTP"
        val https         : Double,    // "HTTPS"

        // TCP flag ratios / counts
        val finFlagNumber : Double,    // "fin_flag_number"
        val pshFlagNumber : Double,    // "psh_flag_number"
        val synFlagNumber : Double,    // "syn_flag_number"
        val finCount      : Double,    // "fin_count"
        val synCount      : Double,    // "syn_count"
        val rstCount      : Double,    // "rst_count"
        val ackCount      : Double,    // "ack_count"
        val urgCount      : Double     // "urg_count"
    )

    // =========================================================================
    // PUBLIC ENTRY POINT
    // =========================================================================
    fun classify(s: NetworkFlowSample): String {
        return nodeRoot(s)
    }

    // =========================================================================
    // ROOT  — line 1:  Min <= 45.26
    // =========================================================================
    private fun nodeRoot(s: NetworkFlowSample): String {
        return if (s.min <= 45.26) {
            node_L(s)
        } else {
            node_R(s)
        }
    }

    // =========================================================================
    // LEFT BRANCH  (Min <= 45.26)
    // line 2:  ICMP <= 0.50
    // =========================================================================
    private fun node_L(s: NetworkFlowSample): String {
        return if (s.icmp <= 0.50) {
            node_L_L(s)
        } else {
            "DDoS-ICMP_Flood"
        }
    }

    private fun node_L_L(s: NetworkFlowSample): String {
        return if (s.variance <= 0.68) {
            "DoS-UDP_Flood"
        } else {
            node_L_L_R(s)
        }
    }

    private fun node_L_L_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166563800.00) {
            node_L_L_R_L(s)
        } else {
            node_L_L_R_R(s)
        }
    }

    private fun node_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 166477944.00) {
            node_L_L_R_L_L(s)
        } else {
            "BenignTraffic"
        }
    }

    private fun node_L_L_R_L_L(s: NetworkFlowSample): String {
        return if (s.max <= 271.20) {
            node_L_L_R_L_L_L(s)
        } else {
            "Recon-OSScan"
        }
    }

    private fun node_L_L_R_L_L_L(s: NetworkFlowSample): String {
        return if (s.totSum <= 957.07) {
            if (s.covariance <= 812.24) "MITM-ArpSpoofing" else "DDoS-ICMP_Flood"
        } else {
            "Recon-PortScan"
        }
    }

    private fun node_L_L_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166728808.00) {
            if (s.std <= 349.22) "MITM-ArpSpoofing" else "DictionaryBruteForce"
        } else {
            node_L_L_R_R_R(s)
        }
    }

    private fun node_L_L_R_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166851128.00) {
            if (s.ackCount <= 0.50) "Recon-HostDiscovery" else "BrowserHijacking"
        } else {
            node_L_L_R_R_R_R(s)
        }
    }

    private fun node_L_L_R_R_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 167250632.00) {
            "DNS_Spoofing"
        } else {
            if (s.headerLength <= 24118.25) "XSS" else "CommandInjection"
        }
    }

    // =========================================================================
    // RIGHT BRANCH  (Min > 45.26)
    // *** Magnitue → magnitude (renamed field) ***
    // =========================================================================
    private fun node_R(s: NetworkFlowSample): String {
        return if (s.magnitude <= 10.37) node_R_L(s) else node_R_R(s)
    }

    private fun node_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83096004.00) node_R_L_L(s) else node_R_L_R(s)
    }

    private fun node_R_L_L(s: NetworkFlowSample): String {
        return if (s.udp <= 0.50) node_R_L_L_L(s) else node_R_L_L_R(s)
    }

    private fun node_R_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83082784.00) node_R_L_L_L_L(s) else "DDoS-SYN_Flood"
    }

    private fun node_R_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83009424.00) node_R_L_L_L_L_L(s) else "DDoS-TCP_Flood"
    }

    private fun node_R_L_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 82966744.00) {
            // *** Magnitue → magnitude ***
            if (s.magnitude <= 10.32) "MITM-ArpSpoofing" else "DoS-TCP_Flood"
        } else {
            "DoS-SYN_Flood"
        }
    }

    private fun node_R_L_L_R(s: NetworkFlowSample): String {
        return if (s.iat <= 78721352.00) node_R_L_L_R_L(s) else "DoS-UDP_Flood"
    }

    private fun node_R_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.headerLength <= 18525.96) {
            if (s.number <= 6.50) "DNS_Spoofing" else "DDoS-UDP_Flood"
        } else {
            node_R_L_L_R_L_R(s)
        }
    }

    private fun node_R_L_L_R_L_R(s: NetworkFlowSample): String {
        return if (s.rate <= 8455.28) {
            if (s.covariance <= 60.82) "DDoS-UDP_Flood" else "MITM-ArpSpoofing"
        } else {
            "DoS-UDP_Flood"
        }
    }

    private fun node_R_L_R(s: NetworkFlowSample): String {
        return if (s.udp <= 0.50) node_R_L_R_L(s) else node_R_L_R_R(s)
    }

    private fun node_R_L_R_L(s: NetworkFlowSample): String {
        return if (s.std <= 1.16) {
            if (s.rstCount <= 0.37) {
                if (s.ackCount <= 0.49) "DDoS-SynonymousIP_Flood" else "DDoS-RSTFINFlood"
            } else {
                "DDoS-PSHACK_Flood"
            }
        } else {
            "DDoS-ICMP_Flood"
        }
    }

    private fun node_R_L_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 91554624.00) "DDoS-UDP_Flood"
        else if (s.iat <= 99678524.00)   "DoS-UDP_Flood"
        else                              "DDoS-UDP_Flood"
    }

    private fun node_R_R(s: NetworkFlowSample): String {
        return if (s.finFlagNumber <= 0.50) node_R_R_L(s) else node_R_R_R(s)
    }

    private fun node_R_R_L(s: NetworkFlowSample): String {
        return if (s.pshFlagNumber <= 0.50) node_R_R_L_L(s) else node_R_R_L_R(s)
    }

    private fun node_R_R_L_L(s: NetworkFlowSample): String {
        return if (s.synFlagNumber <= 0.50) node_R_R_L_L_L(s) else node_R_R_L_L_R(s)
    }

    private fun node_R_R_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 82964324.00) node_R_R_L_L_L_L(s) else node_R_R_L_L_L_R(s)
    }

    private fun node_R_R_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 82131012.00) node_R_R_L_L_L_L_L(s) else "DoS-TCP_Flood"
    }

    private fun node_R_R_L_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.urgCount <= 8.05) node_R_R_L_L_L_L_L_L(s)
        else node_R_R_L_L_L_L_L_R(s)
    }

    private fun node_R_R_L_L_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.headerLength <= 171279.00) node_R_R_L_L_L_L_L_L_L(s)
        else node_R_R_L_L_L_L_L_L_R(s)
    }

    private fun node_R_R_L_L_L_L_L_L_L(s: NetworkFlowSample): String {
        return UNKNOWN_TRUNCATED
    }

    private fun node_R_R_L_L_L_L_L_L_R(s: NetworkFlowSample): String {
        return if (s.number <= 5.75) UNKNOWN_TRUNCATED
        else {
            // *** Magnitue → magnitude ***
            if (s.magnitude <= 33.64) "Mirai-udpplain" else UNKNOWN_TRUNCATED
        }
    }

    private fun node_R_R_L_L_L_L_L_R(s: NetworkFlowSample): String {
        return UNKNOWN_TRUNCATED
    }

    private fun node_R_R_L_L_L_R(s: NetworkFlowSample): String {
        return if (s.totSum <= 627.13) node_R_R_L_L_L_R_L(s) else node_R_R_L_L_L_R_R(s)
    }

    private fun node_R_R_L_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.headerLength <= 80.98) node_R_R_L_L_L_R_L_L(s)
        else node_R_R_L_L_L_R_L_R(s)
    }

    private fun node_R_R_L_L_L_R_L_L(s: NetworkFlowSample): String {
        return if (s.finCount <= 0.14) {
            if (s.iat <= 83102676.00) "DDoS-TCP_Flood"
            else if (s.iat <= 99593208.00) UNKNOWN_TRUNCATED
            else "DDoS-TCP_Flood"
        } else {
            if (s.iat <= 83201588.00) {
                if (s.iat <= 83037416.00) "DoS-SYN_Flood" else "DDoS-SYN_Flood"
            } else {
                if (s.iat <= 91421128.00) "DDoS-PSHACK_Flood" else UNKNOWN_TRUNCATED
            }
        }
    }

    private fun node_R_R_L_L_L_R_L_R(s: NetworkFlowSample): String {
        return if (s.protocolType <= 7.62) {
            if (s.finCount <= 0.32) {
                if (s.protocolType <= 4.66) "DDoS-ICMP_Flood" else "DDoS-TCP_Flood"
            } else {
                if (s.synCount <= 0.30) "DDoS-PSHACK_Flood" else UNKNOWN_TRUNCATED
            }
        } else {
            if (s.iat <= 83065444.00) "DoS-UDP_Flood"
            else if (s.min <= 57.60)  "DDoS-UDP_Flood"
            else                       "DDoS-RSTFINFlood"
        }
    }

    private fun node_R_R_L_L_L_R_R(s: NetworkFlowSample): String {
        return if (s.protocolType <= 17.92) {
            node_R_R_L_L_L_R_R_L(s)
        } else {
            if (s.iat <= 83670368.00)       "Mirai-greip_flood"
            else if (s.iat <= 91995928.00)  "Mirai-greeth_flood"
            else if (s.max <= 579.82)       "Mirai-greip_flood"
            else                             "Mirai-greeth_flood"
        }
    }

    private fun node_R_R_L_L_L_R_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83033336.00) {
            if (s.iat <= 83003400.00) {
                if (s.iat <= 82992556.00) "DoS-SYN_Flood" else "DoS-HTTP_Flood"
            } else "DoS-UDP_Flood"
        } else {
            UNKNOWN_TRUNCATED
        }
    }

    private fun node_R_R_L_L_R(s: NetworkFlowSample): String {
        return if (s.iat <= 83301252.00) node_R_R_L_L_R_L(s) else node_R_R_L_L_R_R(s)
    }

    private fun node_R_R_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83039908.00) {
            if (s.iat <= 75198536.00) node_R_R_L_L_R_L_LL(s)
            else node_R_R_L_L_R_L_LR(s)
        } else {
            if (s.iat <= 83126288.00) "DDoS-SYN_Flood"
            else if (s.min <= 56.52)  "VulnerabilityScan"
            else                       "DDoS-HTTP_Flood"
        }
    }

    private fun node_R_R_L_L_R_L_LL(s: NetworkFlowSample): String {
        return if (s.finCount <= 0.45) {
            if (s.totSize <= 56.03) {
                if (s.flowDuration <= 0.36) "DDoS-SYN_Flood" else UNKNOWN_TRUNCATED
            } else {
                if (s.headerLength <= 1491.40) UNKNOWN_TRUNCATED else "Recon-OSScan"
            }
        } else {
            "Recon-HostDiscovery"
        }
    }

    private fun node_R_R_L_L_R_L_LR(s: NetworkFlowSample): String {
        return if (s.iat <= 82992708.00) {
            if (s.totSum <= 558.40) {
                if (s.iat <= 78293624.00) "DoS-SYN_Flood" else UNKNOWN_TRUNCATED
            } else "DoS-SYN_Flood"
        } else {
            "DoS-HTTP_Flood"
        }
    }

    private fun node_R_R_L_L_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 83378744.00) "DDoS-SynonymousIP_Flood"
        else if (s.iat <= 99873420.00) {
            if (s.totSize <= 71.30) {
                if (s.iat <= 91531084.00) "DDoS-SYN_Flood"
                else if (s.iat <= 99637756.00) "DoS-SYN_Flood"
                else "DDoS-SYN_Flood"
            } else "DDoS-HTTP_Flood"
        } else {
            if (s.iat <= 166642840.00) {
                if (s.iat <= 166430048.00) {
                    if (s.weight <= 193.08) UNKNOWN_TRUNCATED else "Recon-PortScan"
                } else "Recon-OSScan"
            } else "Recon-HostDiscovery"
        }
    }

    private fun node_R_R_L_R(s: NetworkFlowSample): String {
        return if (s.urgCount <= 3.00) {
            if (s.variance <= 0.70) "DDoS-PSHACK_Flood"
            else node_R_R_L_R_L_R(s)
        } else {
            node_R_R_L_R_R(s)
        }
    }

    private fun node_R_R_L_R_L_R(s: NetworkFlowSample): String {
        return if (s.flowDuration <= 0.10) "Recon-PortScan"
        else if (s.protocolType <= 5.70)   "BenignTraffic"
        else if (s.covariance <= 288181.58) "DDoS-SlowLoris"
        else                                "DDoS-HTTP_Flood"
    }

    private fun node_R_R_L_R_R(s: NetworkFlowSample): String {
        return if (s.srate <= 173.64) node_R_R_L_R_R_L(s) else node_R_R_L_R_R_R(s)
    }

    private fun node_R_R_L_R_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 166850688.00) {
            if (s.http <= 0.50) node_R_R_L_R_R_L_noHTTP(s)
            else node_R_R_L_R_R_L_HTTP(s)
        } else {
            // *** Magnitue → magnitude ***
            if (s.magnitude <= 16.16) "XSS" else "DNS_Spoofing"
        }
    }

    private fun node_R_R_L_R_R_L_noHTTP(s: NetworkFlowSample): String {
        return if (s.iat <= 166478016.00) {
            if (s.iat <= 0.01) {
                if (s.rstCount <= 565.65) UNKNOWN_TRUNCATED else "MITM-ArpSpoofing"
            } else {
                UNKNOWN_TRUNCATED
            }
        } else {
            if (s.iat <= 166563632.00)      "BenignTraffic"
            else if (s.iat <= 166605496.00) "DictionaryBruteForce"
            else                             UNKNOWN_TRUNCATED
        }
    }

    private fun node_R_R_L_R_R_L_HTTP(s: NetworkFlowSample): String {
        return if (s.iat <= 83188848.00) {
            if (s.rate <= 2.69) "XSS" else "DoS-HTTP_Flood"
        } else {
            "DDoS-SlowLoris"
        }
    }

    private fun node_R_R_L_R_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166730440.00) {
            if (s.https <= 0.50) {
                if (s.duration <= 60.85) "BenignTraffic" else "DictionaryBruteForce"
            } else {
                node_R_R_L_R_R_R_HTTPS(s)
            }
        } else {
            if (s.duration <= 190.05) "DNS_Spoofing" else "Recon-HostDiscovery"
        }
    }

    private fun node_R_R_L_R_R_R_HTTPS(s: NetworkFlowSample): String {
        return if (s.headerLength <= 218869.41) {
            if (s.urgCount <= 23.86) {
                if (s.urgCount <= 8.25) "Recon-OSScan" else "MITM-ArpSpoofing"
            } else {
                if (s.variance <= 0.35) "Recon-HostDiscovery" else UNKNOWN_TRUNCATED
            }
        } else {
            if (s.totSize <= 1576.93) "DDoS-TCP_Flood"
            else if (s.flowDuration <= 23.52) UNKNOWN_TRUNCATED
            else "DNS_Spoofing"
        }
    }

    private fun node_R_R_R(s: NetworkFlowSample): String {
        return if (s.synCount <= 0.75) "DDoS-RSTFINFlood"
        else if (s.radius <= 4.71)     "DDoS-SlowLoris"
        else                            "DoS-SYN_Flood"
    }
}
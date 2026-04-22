package com.muhammad.networkscan

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
 */
object NetworkTrafficClassifier {

    // -------------------------------------------------------------------------
    // Return value for branches that were truncated in the exported rule file.
    // -------------------------------------------------------------------------
    const val UNKNOWN_TRUNCATED = "UNKNOWN_TRUNCATED (Rule coverage limitation)"

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
        val min: Double,               // "Min"
        val max: Double,               // "Max"
        val std: Double,               // "Std"
        val variance: Double,          // "Variance"
        val iat: Double,               // "IAT"
        val totSum: Double,            // "Tot sum"
        val totSize: Double,           // "Tot size"
        val headerLength: Double,      // "Header_Length"
        val number: Double,            // "Number"
        val rate: Double,              // "Rate"
        val srate: Double,             // "Srate"
        val covariance: Double,        // "Covariance"

        // *** RENAMED: dataset column is "Magnitue" (typo) → mapped to [magnitude] here ***
        val magnitude: Double,         // "Magnitue"  ← check your CSV column name!

        val radius: Double,            // "Radius"
        val weight: Double,            // "Weight"
        val duration: Double,          // "Duration"
        val flowDuration: Double,      // "flow_duration"
        val protocolType: Double,      // "Protocol Type"

        // Protocol flags — stored as 0.0 or 1.0 in the dataset; split at 0.50
        val icmp: Double,              // "ICMP"
        val udp: Double,               // "UDP"
        val http: Double,              // "HTTP"
        val https: Double,             // "HTTPS"

        // TCP flag ratios / counts
        val finFlagNumber: Double,     // "fin_flag_number"
        val pshFlagNumber: Double,     // "psh_flag_number"
        val synFlagNumber: Double,     // "syn_flag_number"
        val finCount: Double,          // "fin_count"
        val synCount: Double,          // "syn_count"
        val rstCount: Double,          // "rst_count"
        val ackCount: Double,          // "ack_count"
        val urgCount: Double           // "urg_count"
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
            node_L(s)          // left  subtree (Min <= 45.26)
        } else {
            node_R(s)          // right subtree (Min >  45.26)
        }
    }

    // =========================================================================
    // LEFT BRANCH  (Min <= 45.26)
    // line 2:  ICMP <= 0.50
    // =========================================================================
    private fun node_L(s: NetworkFlowSample): String {
        return if (s.icmp <= 0.50) {
            node_L_L(s)        // ICMP <= 0.50
        } else {
            // line 41:  class: DDoS-ICMP_Flood
            "DDoS-ICMP_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // Min <= 45.26, ICMP <= 0.50
    // line 3:  Variance <= 0.68
    // -------------------------------------------------------------------------
    private fun node_L_L(s: NetworkFlowSample): String {
        return if (s.variance <= 0.68) {
            // line 4:  class: DoS-UDP_Flood
            "DoS-UDP_Flood"
        } else {
            node_L_L_R(s)      // Variance > 0.68
        }
    }

    // -------------------------------------------------------------------------
    // Min <= 45.26, ICMP <= 0.50, Variance > 0.68
    // line 6:  IAT <= 166563800.00
    // -------------------------------------------------------------------------
    private fun node_L_L_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166563800.00) {
            node_L_L_R_L(s)    // IAT <= 166563800
        } else {
            node_L_L_R_R(s)    // IAT >  166563800
        }
    }

    // -------------------------------------------------------------------------
    // ...Variance > 0.68, IAT <= 166563800.00
    // line 7:  IAT <= 166477944.00
    // -------------------------------------------------------------------------
    private fun node_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 166477944.00) {
            node_L_L_R_L_L(s)
        } else {
            // line 18-19: IAT > 166477944  →  class: BenignTraffic
            "BenignTraffic"
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT <= 166477944.00
    // line 8:  Max <= 271.20
    // -------------------------------------------------------------------------
    private fun node_L_L_R_L_L(s: NetworkFlowSample): String {
        return if (s.max <= 271.20) {
            node_L_L_R_L_L_L(s)
        } else {
            // line 17:  class: Recon-OSScan
            "Recon-OSScan"
        }
    }

    // -------------------------------------------------------------------------
    // ...Max <= 271.20
    // line 9:  Tot sum <= 957.07
    // -------------------------------------------------------------------------
    private fun node_L_L_R_L_L_L(s: NetworkFlowSample): String {
        return if (s.totSum <= 957.07) {
            // line 10:  Covariance <= 812.24
            if (s.covariance <= 812.24) {
                // line 11:  class: MITM-ArpSpoofing
                "MITM-ArpSpoofing"
            } else {
                // line 13:  class: DDoS-ICMP_Flood
                "DDoS-ICMP_Flood"
            }
        } else {
            // line 15:  class: Recon-PortScan
            "Recon-PortScan"
        }
    }

    // -------------------------------------------------------------------------
    // ...Variance > 0.68, IAT > 166563800.00
    // line 21:  IAT <= 166728808.00
    // -------------------------------------------------------------------------
    private fun node_L_L_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166728808.00) {
            // line 22:  Std <= 349.22
            if (s.std <= 349.22) {
                // line 23:  class: MITM-ArpSpoofing
                "MITM-ArpSpoofing"
            } else {
                // line 25:  class: DictionaryBruteForce
                "DictionaryBruteForce"
            }
        } else {
            node_L_L_R_R_R(s)  // IAT > 166728808
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 166728808.00
    // line 27:  IAT <= 166851128.00
    // -------------------------------------------------------------------------
    private fun node_L_L_R_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166851128.00) {
            // line 28:  ack_count <= 0.50
            if (s.ackCount <= 0.50) {
                // line 29:  class: Recon-HostDiscovery
                "Recon-HostDiscovery"
            } else {
                // line 31:  class: BrowserHijacking
                "BrowserHijacking"
            }
        } else {
            node_L_L_R_R_R_R(s)  // IAT > 166851128
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 166851128.00
    // line 33:  IAT <= 167250632.00
    // -------------------------------------------------------------------------
    private fun node_L_L_R_R_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 167250632.00) {
            // line 34:  class: DNS_Spoofing
            "DNS_Spoofing"
        } else {
            // line 36:  Header_Length <= 24118.25
            if (s.headerLength <= 24118.25) {
                // line 37:  class: XSS
                "XSS"
            } else {
                // line 39:  class: CommandInjection
                "CommandInjection"
            }
        }
    }

    // =========================================================================
    // RIGHT BRANCH  (Min > 45.26)
    // line 43:  Magnitue <= 10.37   ← "Magnitue" is the original column name
    // =========================================================================
    private fun node_R(s: NetworkFlowSample): String {
        return if (s.magnitude <= 10.37) {   // *** renamed field: magnitude ***
            node_R_L(s)        // magnitude <= 10.37
        } else {
            node_R_R(s)        // magnitude >  10.37
        }
    }

    // =========================================================================
    // Min > 45.26, magnitude <= 10.37
    // line 44:  IAT <= 83096004.00
    // =========================================================================
    private fun node_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83096004.00) {
            node_R_L_L(s)
        } else {
            node_R_L_R(s)
        }
    }

    // -------------------------------------------------------------------------
    // ...magnitude <= 10.37, IAT <= 83096004.00
    // line 45:  UDP <= 0.50
    // -------------------------------------------------------------------------
    private fun node_R_L_L(s: NetworkFlowSample): String {
        return if (s.udp <= 0.50) {
            node_R_L_L_L(s)   // UDP <= 0.50 (non-UDP)
        } else {
            node_R_L_L_R(s)   // UDP >  0.50
        }
    }

    // -------------------------------------------------------------------------
    // ...UDP <= 0.50, IAT <= 83096004
    // line 46:  IAT <= 83082784.00
    // -------------------------------------------------------------------------
    private fun node_R_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83082784.00) {
            node_R_L_L_L_L(s)
        } else {
            // line 58:  class: DDoS-SYN_Flood
            "DDoS-SYN_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT <= 83082784.00
    // line 47:  IAT <= 83009424.00
    // -------------------------------------------------------------------------
    private fun node_R_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83009424.00) {
            node_R_L_L_L_L_L(s)
        } else {
            // line 56:  class: DDoS-TCP_Flood
            "DDoS-TCP_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT <= 83009424.00
    // line 48:  IAT <= 82966744.00
    // -------------------------------------------------------------------------
    private fun node_R_L_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 82966744.00) {
            // line 49:  Magnitue <= 10.32  *** renamed: magnitude ***
            if (s.magnitude <= 10.32) {
                // line 50:  class: MITM-ArpSpoofing
                "MITM-ArpSpoofing"
            } else {
                // line 52:  class: DoS-TCP_Flood
                "DoS-TCP_Flood"
            }
        } else {
            // line 54:  class: DoS-SYN_Flood
            "DoS-SYN_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // ...UDP > 0.50, IAT <= 83096004
    // line 60:  IAT <= 78721352.00
    // -------------------------------------------------------------------------
    private fun node_R_L_L_R(s: NetworkFlowSample): String {
        return if (s.iat <= 78721352.00) {
            node_R_L_L_R_L(s)
        } else {
            // line 75:  class: DoS-UDP_Flood
            "DoS-UDP_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // ...UDP > 0.50, IAT <= 78721352
    // line 61:  Header_Length <= 18525.96
    // -------------------------------------------------------------------------
    private fun node_R_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.headerLength <= 18525.96) {
            // line 62:  Number <= 6.50
            if (s.number <= 6.50) {
                // line 63:  class: DNS_Spoofing
                "DNS_Spoofing"
            } else {
                // line 65:  class: DDoS-UDP_Flood
                "DDoS-UDP_Flood"
            }
        } else {
            node_R_L_L_R_L_R(s)  // Header_Length > 18525.96
        }
    }

    // -------------------------------------------------------------------------
    // ...Header_Length > 18525.96
    // line 67:  Rate <= 8455.28
    // -------------------------------------------------------------------------
    private fun node_R_L_L_R_L_R(s: NetworkFlowSample): String {
        return if (s.rate <= 8455.28) {
            // line 68:  Covariance <= 60.82
            if (s.covariance <= 60.82) {
                // line 69:  class: DDoS-UDP_Flood
                "DDoS-UDP_Flood"
            } else {
                // line 71:  class: MITM-ArpSpoofing
                "MITM-ArpSpoofing"
            }
        } else {
            // line 73:  class: DoS-UDP_Flood
            "DoS-UDP_Flood"
        }
    }

    // =========================================================================
    // Min > 45.26, magnitude <= 10.37, IAT > 83096004.00
    // line 77:  UDP <= 0.50
    // =========================================================================
    private fun node_R_L_R(s: NetworkFlowSample): String {
        return if (s.udp <= 0.50) {
            node_R_L_R_L(s)
        } else {
            node_R_L_R_R(s)
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 83096004, UDP <= 0.50
    // line 78:  Std <= 1.16
    // -------------------------------------------------------------------------
    private fun node_R_L_R_L(s: NetworkFlowSample): String {
        return if (s.std <= 1.16) {
            // line 79:  rst_count <= 0.37
            if (s.rstCount <= 0.37) {
                // line 80:  ack_count <= 0.49
                if (s.ackCount <= 0.49) {
                    // line 81:  class: DDoS-SynonymousIP_Flood
                    "DDoS-SynonymousIP_Flood"
                } else {
                    // line 83:  class: DDoS-RSTFINFlood
                    "DDoS-RSTFINFlood"
                }
            } else {
                // line 85:  class: DDoS-PSHACK_Flood
                "DDoS-PSHACK_Flood"
            }
        } else {
            // line 87:  class: DDoS-ICMP_Flood
            "DDoS-ICMP_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 83096004, UDP > 0.50
    // line 89:  IAT <= 91554624.00
    // -------------------------------------------------------------------------
    private fun node_R_L_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 91554624.00) {
            // line 90:  class: DDoS-UDP_Flood
            "DDoS-UDP_Flood"
        } else {
            // line 92:  IAT <= 99678524.00
            if (s.iat <= 99678524.00) {
                // line 93:  class: DoS-UDP_Flood
                "DoS-UDP_Flood"
            } else {
                // line 95:  class: DDoS-UDP_Flood
                "DDoS-UDP_Flood"
            }
        }
    }

    // =========================================================================
    // Min > 45.26, magnitude > 10.37
    // line 97:  fin_flag_number <= 0.50
    // =========================================================================
    private fun node_R_R(s: NetworkFlowSample): String {
        return if (s.finFlagNumber <= 0.50) {
            node_R_R_L(s)      // fin_flag_number <= 0.50
        } else {
            node_R_R_R(s)      // fin_flag_number >  0.50
        }
    }

    // =========================================================================
    // ...magnitude > 10.37, fin_flag_number <= 0.50
    // line 98:  psh_flag_number <= 0.50
    // =========================================================================
    private fun node_R_R_L(s: NetworkFlowSample): String {
        return if (s.pshFlagNumber <= 0.50) {
            node_R_R_L_L(s)    // psh_flag_number <= 0.50
        } else {
            node_R_R_L_R(s)    // psh_flag_number >  0.50
        }
    }

    // =========================================================================
    // ...fin_flag_number <= 0.50, psh_flag_number <= 0.50
    // line 99:  syn_flag_number <= 0.50
    // =========================================================================
    private fun node_R_R_L_L(s: NetworkFlowSample): String {
        return if (s.synFlagNumber <= 0.50) {
            node_R_R_L_L_L(s)  // syn_flag_number <= 0.50
        } else {
            node_R_R_L_L_R(s)  // syn_flag_number >  0.50
        }
    }

    // =========================================================================
    // ...syn_flag_number <= 0.50
    // line 100: IAT <= 82964324.00
    // =========================================================================
    private fun node_R_R_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 82964324.00) {
            node_R_R_L_L_L_L(s)
        } else {
            node_R_R_L_L_L_R(s)   // IAT > 82964324
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT <= 82964324.00
    // line 101: IAT <= 82131012.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.iat <= 82131012.00) {
            node_R_R_L_L_L_L_L(s)
        } else {
            // line 149:  class: DoS-TCP_Flood
            "DoS-TCP_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT <= 82131012.00
    // line 102: urg_count <= 8.05
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.urgCount <= 8.05) {
            node_R_R_L_L_L_L_L_L(s)
        } else {
            node_R_R_L_L_L_L_L_R(s)   // urg_count > 8.05
        }
    }

    // -------------------------------------------------------------------------
    // ...urg_count <= 8.05
    // line 103: Header_Length <= 171279.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.headerLength <= 171279.00) {
            node_R_R_L_L_L_L_L_L_L(s)
        } else {
            node_R_R_L_L_L_L_L_L_R(s)  // Header_Length > 171279
        }
    }

    // -------------------------------------------------------------------------
    // ...Header_Length <= 171279.00
    // line 104: fin_count <= 0.05
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_L_L_L_L(s: NetworkFlowSample): String {
        return if (s.finCount <= 0.05) {
            // line 105-108: two truncated sub-branches on Header_Length <= 186.07
            // (depth 7 and depth 16 — both unknown)
            UNKNOWN_TRUNCATED
        } else {
            // line 110: syn_count <= 0.75
            // line 111-113: both branches truncated (depth 9 and depth 8)
            UNKNOWN_TRUNCATED
        }
    }

    // -------------------------------------------------------------------------
    // ...Header_Length > 171279.00
    // line 115: Number <= 5.75
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_L_L_L_R(s: NetworkFlowSample): String {
        return if (s.number <= 5.75) {
            // line 116-119: HTTPS <= / > 0.50 both truncated (depth 14 and depth 5)
            UNKNOWN_TRUNCATED
        } else {
            // line 120: Number > 5.75
            // line 121: Magnitue <= 33.64  *** renamed: magnitude ***
            if (s.magnitude <= 33.64) {
                // line 122: class: Mirai-udpplain
                "Mirai-udpplain"
            } else {
                // line 124: truncated branch of depth 2
                UNKNOWN_TRUNCATED
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...urg_count > 8.05
    // line 126: flow_duration <= 163.03
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_L_L_R(s: NetworkFlowSample): String {
        return if (s.flowDuration <= 163.03) {
            // line 127-136: Rate split, then further truncated branches (depths 14,30,14,10)
            // No leaf classes are reachable without the truncated sub-trees.
            UNKNOWN_TRUNCATED
        } else {
            // line 137: flow_duration > 163.03
            // line 138: IAT <= 0.02
            if (s.iat <= 0.02) {
                // line 139-142: Header_Length split — both branches truncated (depth 10, 5)
                UNKNOWN_TRUNCATED
            } else {
                // line 143: IAT > 0.02
                // line 144: Tot sum <= 465.75 — both branches truncated (depth 4, 13)
                UNKNOWN_TRUNCATED
            }
        }
    }

    // =========================================================================
    // ...syn_flag_number <= 0.50, IAT > 82964324.00
    // line 150: Tot sum <= 627.13
    // =========================================================================
    private fun node_R_R_L_L_L_R(s: NetworkFlowSample): String {
        return if (s.totSum <= 627.13) {
            node_R_R_L_L_L_R_L(s)
        } else {
            node_R_R_L_L_L_R_R(s)  // Tot sum > 627.13
        }
    }

    // -------------------------------------------------------------------------
    // ...Tot sum <= 627.13
    // line 152: Header_Length <= 80.98
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.headerLength <= 80.98) {
            node_R_R_L_L_L_R_L_L(s)
        } else {
            node_R_R_L_L_L_R_L_R(s)  // Header_Length > 80.98
        }
    }

    // -------------------------------------------------------------------------
    // ...Header_Length <= 80.98
    // line 153: fin_count <= 0.14
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_R_L_L(s: NetworkFlowSample): String {
        return if (s.finCount <= 0.14) {
            // line 154: IAT <= 83102676.00
            if (s.iat <= 83102676.00) {
                // line 155: class: DDoS-TCP_Flood
                "DDoS-TCP_Flood"
            } else {
                // line 157: IAT <= 99593208.00
                if (s.iat <= 99593208.00) {
                    // line 158: truncated branch of depth 2
                    UNKNOWN_TRUNCATED
                } else {
                    // line 160: class: DDoS-TCP_Flood
                    "DDoS-TCP_Flood"
                }
            }
        } else {
            // line 161: fin_count > 0.14
            // line 162: IAT <= 83201588.00
            if (s.iat <= 83201588.00) {
                // line 163: IAT <= 83037416.00
                if (s.iat <= 83037416.00) {
                    // line 164: class: DoS-SYN_Flood
                    "DoS-SYN_Flood"
                } else {
                    // line 166: class: DDoS-SYN_Flood
                    "DDoS-SYN_Flood"
                }
            } else {
                // line 168: IAT <= 91421128.00
                if (s.iat <= 91421128.00) {
                    // line 169: class: DDoS-PSHACK_Flood
                    "DDoS-PSHACK_Flood"
                } else {
                    // line 171: truncated branch of depth 2
                    UNKNOWN_TRUNCATED
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...Header_Length > 80.98
    // line 173: Protocol Type <= 7.62
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_R_L_R(s: NetworkFlowSample): String {
        return if (s.protocolType <= 7.62) {
            // line 174: fin_count <= 0.32
            if (s.finCount <= 0.32) {
                // line 175: Protocol Type <= 4.66
                if (s.protocolType <= 4.66) {
                    // line 176: class: DDoS-ICMP_Flood
                    "DDoS-ICMP_Flood"
                } else {
                    // line 178: class: DDoS-TCP_Flood
                    "DDoS-TCP_Flood"
                }
            } else {
                // line 180: syn_count <= 0.30
                if (s.synCount <= 0.30) {
                    // line 181: class: DDoS-PSHACK_Flood
                    "DDoS-PSHACK_Flood"
                } else {
                    // line 183: truncated branch of depth 4
                    UNKNOWN_TRUNCATED
                }
            }
        } else {
            // line 184: Protocol Type > 7.62
            // line 185: IAT <= 83065444.00
            if (s.iat <= 83065444.00) {
                // line 186: class: DoS-UDP_Flood
                "DoS-UDP_Flood"
            } else {
                // line 188: Min <= 57.60
                if (s.min <= 57.60) {
                    // line 189: class: DDoS-UDP_Flood
                    "DDoS-UDP_Flood"
                } else {
                    // line 191: class: DDoS-RSTFINFlood
                    "DDoS-RSTFINFlood"
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...Tot sum > 627.13
    // line 193: Protocol Type <= 17.92
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_R_R(s: NetworkFlowSample): String {
        return if (s.protocolType <= 17.92) {
            node_R_R_L_L_L_R_R_L(s)
        } else {
            // line 213: Protocol Type > 17.92  — Mirai GRE variants
            // line 214: IAT <= 83670368.00
            if (s.iat <= 83670368.00) {
                // line 215: class: Mirai-greip_flood
                "Mirai-greip_flood"
            } else {
                // line 217: IAT <= 91995928.00
                if (s.iat <= 91995928.00) {
                    // line 218: class: Mirai-greeth_flood
                    "Mirai-greeth_flood"
                } else {
                    // line 220: Max <= 579.82
                    if (s.max <= 579.82) {
                        // line 221: class: Mirai-greip_flood
                        "Mirai-greip_flood"
                    } else {
                        // line 223: class: Mirai-greeth_flood
                        "Mirai-greeth_flood"
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...Protocol Type <= 17.92
    // line 194: IAT <= 83033336.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_R_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83033336.00) {
            // line 195: IAT <= 83003400.00
            if (s.iat <= 83003400.00) {
                // line 196: IAT <= 82992556.00
                if (s.iat <= 82992556.00) {
                    // line 197: class: DoS-SYN_Flood
                    "DoS-SYN_Flood"
                } else {
                    // line 199: class: DoS-HTTP_Flood
                    "DoS-HTTP_Flood"
                }
            } else {
                // line 201: class: DoS-UDP_Flood
                "DoS-UDP_Flood"
            }
        } else {
            // line 202: IAT > 83033336.00
            node_R_R_L_L_L_R_R_L_R(s)
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 83033336.00
    // line 203: Min <= 431.13
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_L_R_R_L_R(s: NetworkFlowSample): String {
        return if (s.min <= 431.13) {
            // line 204-207: ICMP split — both branches truncated (depth 16, depth 3)
            UNKNOWN_TRUNCATED
        } else {
            // line 208: Min > 431.13
            // line 209: Magnitue <= 37.98  *** renamed: magnitude ***
            if (s.magnitude <= 37.98) {
                // line 210: truncated branch of depth 2
                UNKNOWN_TRUNCATED
            } else {
                // line 212: truncated branch of depth 12
                UNKNOWN_TRUNCATED
            }
        }
    }

    // =========================================================================
    // ...syn_flag_number > 0.50
    // line 225: IAT <= 83301252.00
    // =========================================================================
    private fun node_R_R_L_L_R(s: NetworkFlowSample): String {
        return if (s.iat <= 83301252.00) {
            node_R_R_L_L_R_L(s)
        } else {
            node_R_R_L_L_R_R(s)  // IAT > 83301252
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT <= 83301252.00
    // line 226: IAT <= 83039908.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 83039908.00) {
            // line 227: IAT <= 75198536.00
            if (s.iat <= 75198536.00) {
                node_R_R_L_L_R_L_LL(s)
            } else {
                node_R_R_L_L_R_L_LR(s)  // IAT > 75198536
            }
        } else {
            // line 252: IAT > 83039908
            // line 253: IAT <= 83126288.00
            if (s.iat <= 83126288.00) {
                // line 254: class: DDoS-SYN_Flood
                "DDoS-SYN_Flood"
            } else {
                // line 256: Min <= 56.52
                if (s.min <= 56.52) {
                    // line 257: class: VulnerabilityScan
                    "VulnerabilityScan"
                } else {
                    // line 259: class: DDoS-HTTP_Flood
                    "DDoS-HTTP_Flood"
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT <= 75198536.00
    // line 228: fin_count <= 0.45
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_R_L_LL(s: NetworkFlowSample): String {
        return if (s.finCount <= 0.45) {
            // line 229: Tot size <= 56.03
            if (s.totSize <= 56.03) {
                // line 230: flow_duration <= 0.36
                if (s.flowDuration <= 0.36) {
                    // line 231: class: DDoS-SYN_Flood
                    "DDoS-SYN_Flood"
                } else {
                    // line 233: truncated branch of depth 4
                    UNKNOWN_TRUNCATED
                }
            } else {
                // line 234: Tot size > 56.03
                // line 235: Header_Length <= 1491.40
                if (s.headerLength <= 1491.40) {
                    // line 236: truncated branch of depth 10
                    UNKNOWN_TRUNCATED
                } else {
                    // line 238: class: Recon-OSScan
                    "Recon-OSScan"
                }
            }
        } else {
            // line 240: class: Recon-HostDiscovery
            "Recon-HostDiscovery"
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 75198536.00 (and <= 83039908)
    // line 242: IAT <= 82992708.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_R_L_LR(s: NetworkFlowSample): String {
        return if (s.iat <= 82992708.00) {
            // line 243: Tot sum <= 558.40
            if (s.totSum <= 558.40) {
                // line 244: IAT <= 78293624.00
                if (s.iat <= 78293624.00) {
                    // line 245: class: DoS-SYN_Flood
                    "DoS-SYN_Flood"
                } else {
                    // line 247: truncated branch of depth 2
                    UNKNOWN_TRUNCATED
                }
            } else {
                // line 249: class: DoS-SYN_Flood
                "DoS-SYN_Flood"
            }
        } else {
            // line 251: class: DoS-HTTP_Flood
            "DoS-HTTP_Flood"
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 83301252.00
    // line 261: IAT <= 83378744.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 83378744.00) {
            // line 262: class: DDoS-SynonymousIP_Flood
            "DDoS-SynonymousIP_Flood"
        } else {
            // line 264: IAT <= 99873420.00
            if (s.iat <= 99873420.00) {
                // line 265: Tot size <= 71.30
                if (s.totSize <= 71.30) {
                    // line 266: IAT <= 91531084.00
                    if (s.iat <= 91531084.00) {
                        // line 267: class: DDoS-SYN_Flood
                        "DDoS-SYN_Flood"
                    } else {
                        // line 269: IAT <= 99637756.00
                        if (s.iat <= 99637756.00) {
                            // line 270: class: DoS-SYN_Flood
                            "DoS-SYN_Flood"
                        } else {
                            // line 272: class: DDoS-SYN_Flood
                            "DDoS-SYN_Flood"
                        }
                    }
                } else {
                    // line 274: class: DDoS-HTTP_Flood
                    "DDoS-HTTP_Flood"
                }
            } else {
                // line 275: IAT > 99873420
                node_R_R_L_L_R_R_far(s)
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...IAT > 99873420.00
    // line 276: IAT <= 166642840.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_L_R_R_far(s: NetworkFlowSample): String {
        return if (s.iat <= 166642840.00) {
            // line 277: IAT <= 166430048.00
            if (s.iat <= 166430048.00) {
                // line 278: Weight <= 193.08
                if (s.weight <= 193.08) {
                    // line 279: truncated branch of depth 2
                    UNKNOWN_TRUNCATED
                } else {
                    // line 281: class: Recon-PortScan
                    "Recon-PortScan"
                }
            } else {
                // line 283: class: Recon-OSScan
                "Recon-OSScan"
            }
        } else {
            // line 285: class: Recon-HostDiscovery
            "Recon-HostDiscovery"
        }
    }

    // =========================================================================
    // ...fin_flag_number <= 0.50, psh_flag_number > 0.50
    // line 287: urg_count <= 3.00
    // =========================================================================
    private fun node_R_R_L_R(s: NetworkFlowSample): String {
        return if (s.urgCount <= 3.00) {
            // line 288: Variance <= 0.70
            if (s.variance <= 0.70) {
                // line 289: class: DDoS-PSHACK_Flood
                "DDoS-PSHACK_Flood"
            } else {
                node_R_R_L_R_L_R(s)  // Variance > 0.70
            }
        } else {
            node_R_R_L_R_R(s)  // urg_count > 3.00
        }
    }

    // -------------------------------------------------------------------------
    // ...urg_count <= 3.00, Variance > 0.70
    // line 291: flow_duration <= 0.10
    // -------------------------------------------------------------------------
    private fun node_R_R_L_R_L_R(s: NetworkFlowSample): String {
        return if (s.flowDuration <= 0.10) {
            // line 292: class: Recon-PortScan
            "Recon-PortScan"
        } else {
            // line 294: Protocol Type <= 5.70
            if (s.protocolType <= 5.70) {
                // line 295: class: BenignTraffic
                "BenignTraffic"
            } else {
                // line 297: Covariance <= 288181.58
                if (s.covariance <= 288181.58) {
                    // line 298: class: DDoS-SlowLoris
                    "DDoS-SlowLoris"
                } else {
                    // line 300: class: DDoS-HTTP_Flood
                    "DDoS-HTTP_Flood"
                }
            }
        }
    }

    // =========================================================================
    // ...psh_flag_number > 0.50, urg_count > 3.00
    // line 302: Srate <= 173.64
    // =========================================================================
    private fun node_R_R_L_R_R(s: NetworkFlowSample): String {
        return if (s.srate <= 173.64) {
            node_R_R_L_R_R_L(s)
        } else {
            node_R_R_L_R_R_R(s)  // Srate > 173.64
        }
    }

    // -------------------------------------------------------------------------
    // ...Srate <= 173.64
    // line 303: IAT <= 166850688.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_R_R_L(s: NetworkFlowSample): String {
        return if (s.iat <= 166850688.00) {
            // line 304: HTTP <= 0.50
            if (s.http <= 0.50) {
                node_R_R_L_R_R_L_noHTTP(s)
            } else {
                node_R_R_L_R_R_L_HTTP(s)  // HTTP > 0.50
            }
        } else {
            // line 332: IAT > 166850688
            // line 333: Magnitue <= 16.16  *** renamed: magnitude ***
            if (s.magnitude <= 16.16) {
                // line 334: class: XSS
                "XSS"
            } else {
                // line 336: class: DNS_Spoofing
                "DNS_Spoofing"
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...HTTP <= 0.50, IAT <= 166850688
    // line 305: IAT <= 166478016.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_R_R_L_noHTTP(s: NetworkFlowSample): String {
        return if (s.iat <= 166478016.00) {
            // line 306: IAT <= 0.01
            if (s.iat <= 0.01) {
                // line 307: rst_count <= 565.65
                if (s.rstCount <= 565.65) {
                    // line 308: truncated branch of depth 6
                    UNKNOWN_TRUNCATED
                } else {
                    // line 310: class: MITM-ArpSpoofing
                    "MITM-ArpSpoofing"
                }
            } else {
                // line 311: IAT > 0.01
                // line 312: IAT <= 0.03
                if (s.iat <= 0.03) {
                    // line 313: truncated branch of depth 7
                    UNKNOWN_TRUNCATED
                } else {
                    // line 315: truncated branch of depth 9
                    UNKNOWN_TRUNCATED
                }
            }
        } else {
            // line 316: IAT > 166478016
            // line 317: IAT <= 166563632.00
            if (s.iat <= 166563632.00) {
                // line 318: class: BenignTraffic
                "BenignTraffic"
            } else {
                // line 320: IAT <= 166605496.00
                if (s.iat <= 166605496.00) {
                    // line 321: class: DictionaryBruteForce
                    "DictionaryBruteForce"
                } else {
                    // line 323: truncated branch of depth 2
                    UNKNOWN_TRUNCATED
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...HTTP > 0.50, IAT <= 166850688
    // line 325: IAT <= 83188848.00
    // -------------------------------------------------------------------------
    private fun node_R_R_L_R_R_L_HTTP(s: NetworkFlowSample): String {
        return if (s.iat <= 83188848.00) {
            // line 326: Rate <= 2.69
            if (s.rate <= 2.69) {
                // line 327: class: XSS
                "XSS"
            } else {
                // line 329: class: DoS-HTTP_Flood
                "DoS-HTTP_Flood"
            }
        } else {
            // line 331: class: DDoS-SlowLoris
            "DDoS-SlowLoris"
        }
    }

    // =========================================================================
    // ...Srate > 173.64
    // line 338: IAT <= 166730440.00
    // =========================================================================
    private fun node_R_R_L_R_R_R(s: NetworkFlowSample): String {
        return if (s.iat <= 166730440.00) {
            // line 339: HTTPS <= 0.50
            if (s.https <= 0.50) {
                // line 340: Duration <= 60.85
                if (s.duration <= 60.85) {
                    // line 341: class: BenignTraffic
                    "BenignTraffic"
                } else {
                    // line 343: class: DictionaryBruteForce
                    "DictionaryBruteForce"
                }
            } else {
                // HTTPS > 0.50
                node_R_R_L_R_R_R_HTTPS(s)
            }
        } else {
            // line 364: IAT > 166730440
            // line 365: Duration <= 190.05
            if (s.duration <= 190.05) {
                // line 366: class: DNS_Spoofing
                "DNS_Spoofing"
            } else {
                // line 368: class: Recon-HostDiscovery
                "Recon-HostDiscovery"
            }
        }
    }

    // -------------------------------------------------------------------------
    // ...Srate > 173.64, IAT <= 166730440, HTTPS > 0.50
    // line 345: Header_Length <= 218869.41
    // -------------------------------------------------------------------------
    private fun node_R_R_L_R_R_R_HTTPS(s: NetworkFlowSample): String {
        return if (s.headerLength <= 218869.41) {
            // line 346: urg_count <= 23.86
            if (s.urgCount <= 23.86) {
                // line 347: urg_count <= 8.25
                if (s.urgCount <= 8.25) {
                    // line 348: class: Recon-OSScan
                    "Recon-OSScan"
                } else {
                    // line 350: class: MITM-ArpSpoofing
                    "MITM-ArpSpoofing"
                }
            } else {
                // line 351: urg_count > 23.86
                // line 352: Variance <= 0.35
                if (s.variance <= 0.35) {
                    // line 353: class: Recon-HostDiscovery
                    "Recon-HostDiscovery"
                } else {
                    // line 355: truncated branch of depth 3
                    UNKNOWN_TRUNCATED
                }
            }
        } else {
            // line 356: Header_Length > 218869.41
            // line 357: Tot size <= 1576.93
            if (s.totSize <= 1576.93) {
                // line 358: class: DDoS-TCP_Flood
                "DDoS-TCP_Flood"
            } else {
                // line 360: flow_duration <= 23.52
                if (s.flowDuration <= 23.52) {
                    // line 361: truncated branch of depth 3
                    UNKNOWN_TRUNCATED
                } else {
                    // line 363: class: DNS_Spoofing
                    "DNS_Spoofing"
                }
            }
        }
    }

    // =========================================================================
    // Min > 45.26, magnitude > 10.37, fin_flag_number > 0.50
    // line 370: syn_count <= 0.75
    // =========================================================================
    private fun node_R_R_R(s: NetworkFlowSample): String {
        return if (s.synCount <= 0.75) {
            // line 371: class: DDoS-RSTFINFlood
            "DDoS-RSTFINFlood"
        } else {
            // line 373: Radius <= 4.71
            if (s.radius <= 4.71) {
                // line 374: class: DDoS-SlowLoris
                "DDoS-SlowLoris"
            } else {
                // line 376: class: DoS-SYN_Flood
                "DoS-SYN_Flood"
            }
        }
    }
}
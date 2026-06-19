package com.muhammad.networkscan.classifier


/**
 * Attack / traffic classification labels produced by the pruned decision tree.
 *
 * This enum mirrors the 23 leaf classes present in `decision_tree_rules_pruned.txt`.
 * NOTE: The following classes exist in the *original* (unpruned) tree but were
 * removed by pruning and are intentionally NOT represented here, per project
 * decision: DDoS-HTTP_Flood, DDoS-SlowLoris, DictionaryBruteForce, Recon-OSScan,
 * Backdoor_Malware, BrowserHijacking. Traffic that would have matched those
 * classes will be classified as the nearest matching pruned-tree leaf instead.
 */
enum class AttackType(val label: String) {
    DDOS_ICMP_FLOOD("DDoS-ICMP_Flood"),
    DOS_UDP_FLOOD("DoS-UDP_Flood"),
    DNS_SPOOFING("DNS_Spoofing"),
    BENIGN_TRAFFIC("BenignTraffic"),
    DDOS_UDP_FLOOD("DDoS-UDP_Flood"),
    DDOS_TCP_FLOOD("DDoS-TCP_Flood"),
    DOS_TCP_FLOOD("DoS-TCP_Flood"),
    DDOS_PSHACK_FLOOD("DDoS-PSHACK_Flood"),
    DDOS_RSTFIN_FLOOD("DDoS-RSTFINFlood"),
    DDOS_ICMP_FRAGMENTATION("DDoS-ICMP_Fragmentation"),
    DDOS_ACK_FRAGMENTATION("DDoS-ACK_Fragmentation"),
    RECON_HOST_DISCOVERY("Recon-HostDiscovery"),
    MITM_ARP_SPOOFING("MITM-ArpSpoofing"),
    MIRAI_UDPPLAIN("Mirai-udpplain"),
    DDOS_UDP_FRAGMENTATION("DDoS-UDP_Fragmentation"),
    MIRAI_GREIP_FLOOD("Mirai-greip_flood"),
    MIRAI_GREETH_FLOOD("Mirai-greeth_flood"),
    DDOS_SYNONYMOUS_IP_FLOOD("DDoS-SynonymousIP_Flood"),
    DDOS_SYN_FLOOD("DDoS-SYN_Flood"),
    DOS_SYN_FLOOD("DoS-SYN_Flood"),
    RECON_PORT_SCAN("Recon-PortScan"),
    DOS_HTTP_FLOOD("DoS-HTTP_Flood"),
    VULNERABILITY_SCAN("VulnerabilityScan")
}

/**
 * Feature vector consumed by [DecisionTreeClassifier].
 *
 * Field names/semantics must match whatever feature engineering produced the
 * training data behind `decision_tree_rules_pruned.txt` (this looks like the
 * CICIoT2023 flow-feature schema). Units and aggregation windows (e.g. is
 * "Rate" packets/sec over the whole flow, or over the capture window?) must
 * match the original feature extraction exactly, or the thresholds below
 * will not generalize to your live traffic.
 *
 * - min / max / avg: packet length statistics (bytes) within the flow window
 * - duration: flow duration (seconds, or whatever unit the training data used)
 * - number: packet count in the flow window
 * - protocolType: encoded transport/network protocol identifier
 * - rate: overall packet rate (packets/sec) for the flow
 * - srate: send-direction packet rate (packets/sec)
 * - totSize: total bytes transferred in the flow window
 * - ackCount / finCount / rstCount / synCount / urgCount: TCP flag counts
 *   within the flow window
 */
data class TrafficFeatures(
    val min: Float,
    val max: Float,
    val avg: Float,
    val duration: Float,
    val number: Float,
    val protocolType: Float,
    val rate: Float,
    val srate: Float,
    val totSize: Float,
    val ackCount: Float,
    val finCount: Float,
    val rstCount: Float,
    val synCount: Float,
    val urgCount: Float
) {
    companion object {
        /**
         * Fixed feature order, in case your capture pipeline emits a flat
         * FloatArray instead of named fields (e.g. coming off a native/JNI
         * pcap parser). Keep this order in sync with [fromArray].
         */
        val FEATURE_ORDER: List<String> = listOf(
            "min", "max", "avg", "duration", "number", "protocolType",
            "rate", "srate", "totSize", "ackCount", "finCount",
            "rstCount", "synCount", "urgCount"
        )

        /**
         * Builds [TrafficFeatures] from a flat array following [FEATURE_ORDER].
         * Throws [IllegalArgumentException] if the array length doesn't match.
         */
        fun fromArray(values: FloatArray): TrafficFeatures {
            require(values.size == FEATURE_ORDER.size) {
                "Expected ${FEATURE_ORDER.size} features, got ${values.size}"
            }
            return TrafficFeatures(
                min = values[0],
                max = values[1],
                avg = values[2],
                duration = values[3],
                number = values[4],
                protocolType = values[5],
                rate = values[6],
                srate = values[7],
                totSize = values[8],
                ackCount = values[9],
                finCount = values[10],
                rstCount = values[11],
                synCount = values[12],
                urgCount = values[13]
            )
        }
    }
}

/**
 * Pure, stateless decision-tree classifier generated directly from
 * `decision_tree_rules_pruned.txt`. No ML runtime/model file is needed --
 * it's a plain nested if/else translation of the pruned tree, so it's cheap
 * enough to call per-flow on a mobile device.
 *
 * Thread-safe (no mutable state). Call [classify] once per flow/window you've
 * aggregated features for.
 */
object DecisionTreeClassifier {

    /**
     * Classifies a single flow/window of traffic into one of [AttackType].
     *
     * @param features aggregated feature values for the flow/window being evaluated
     * @return the predicted [AttackType]
     */
    fun classify(features: TrafficFeatures): AttackType {
        return if (features.min <= 52.24f) {
            if (features.protocolType <= 3.77f) {
                AttackType.DDOS_ICMP_FLOOD
            } else {
                if (features.srate <= 287.63f) {
                    if (features.min <= 42.99f) {
                        AttackType.DOS_UDP_FLOOD
                    } else {
                        if (features.rstCount <= 44.05f) {
                            AttackType.DNS_SPOOFING
                        } else {
                            AttackType.BENIGN_TRAFFIC
                        }
                    }
                } else {
                    if (features.rate <= 10688.36f) {
                        if (features.totSize <= 50.39f) {
                            AttackType.DDOS_UDP_FLOOD
                        } else {
                            AttackType.DDOS_UDP_FLOOD
                        }
                    } else {
                        if (features.duration <= 65.74f) {
                            if (features.srate <= 35982.31f) {
                                if (features.srate <= 14154.9f) {
                                    AttackType.DDOS_UDP_FLOOD
                                } else {
                                    AttackType.DOS_UDP_FLOOD
                                }
                            } else {
                                AttackType.DDOS_UDP_FLOOD
                            }
                        } else {
                            AttackType.DOS_UDP_FLOOD
                        }
                    }
                }
            }
        } else {
            if (features.synCount <= 0.39f) {
                if (features.avg <= 65.75f) {
                    if (features.ackCount <= 0.51f) {
                        if (features.urgCount <= 0.55f) {
                            if (features.srate <= 0.55f) {
                                if (features.rate <= 0.01f) {
                                    AttackType.DDOS_TCP_FLOOD
                                } else {
                                    AttackType.DOS_TCP_FLOOD
                                }
                            } else {
                                if (features.protocolType <= 7.04f) {
                                    if (features.finCount <= 0.1f) {
                                        if (features.rate <= 16.67f) {
                                            AttackType.DDOS_TCP_FLOOD
                                        } else {
                                            AttackType.DDOS_TCP_FLOOD
                                        }
                                    } else {
                                        AttackType.DOS_TCP_FLOOD
                                    }
                                } else {
                                    AttackType.DOS_UDP_FLOOD
                                }
                            }
                        } else {
                            if (features.rstCount <= 2.23f) {
                                AttackType.DDOS_PSHACK_FLOOD
                            } else {
                                AttackType.DOS_TCP_FLOOD
                            }
                        }
                    } else {
                        AttackType.DDOS_RSTFIN_FLOOD
                    }
                } else {
                    if (features.protocolType <= 19.7f) {
                        if (features.protocolType <= 13.72f) {
                            if (features.rstCount <= 1.59f) {
                                if (features.protocolType <= 5.13f) {
                                    AttackType.DDOS_ICMP_FRAGMENTATION
                                } else {
                                    if (features.totSize <= 332.28f) {
                                        if (features.min <= 143.78f) {
                                            if (features.protocolType <= 7.99f) {
                                                AttackType.DOS_TCP_FLOOD
                                            } else {
                                                AttackType.DOS_UDP_FLOOD
                                            }
                                        } else {
                                            AttackType.DDOS_TCP_FLOOD
                                        }
                                    } else {
                                        AttackType.DDOS_ACK_FRAGMENTATION
                                    }
                                }
                            } else {
                                if (features.srate <= 116.72f) {
                                    if (features.rstCount <= 67.2f) {
                                        AttackType.BENIGN_TRAFFIC
                                    } else {
                                        if (features.rate <= 2.63f) {
                                            AttackType.RECON_HOST_DISCOVERY
                                        } else {
                                            AttackType.BENIGN_TRAFFIC
                                        }
                                    }
                                } else {
                                    if (features.rstCount <= 2446.65f) {
                                        if (features.ackCount <= 0.0f) {
                                            AttackType.MITM_ARP_SPOOFING
                                        } else {
                                            AttackType.DDOS_RSTFIN_FLOOD
                                        }
                                    } else {
                                        AttackType.MITM_ARP_SPOOFING
                                    }
                                }
                            }
                        } else {
                            if (features.avg <= 434.48f) {
                                if (features.min <= 120.54f) {
                                    AttackType.DOS_UDP_FLOOD
                                } else {
                                    if (features.avg <= 252.12f) {
                                        AttackType.DOS_UDP_FLOOD
                                    } else {
                                        AttackType.DNS_SPOOFING
                                    }
                                }
                            } else {
                                if (features.max <= 750.73f) {
                                    AttackType.MIRAI_UDPPLAIN
                                } else {
                                    if (features.max <= 1303.68f) {
                                        AttackType.MITM_ARP_SPOOFING
                                    } else {
                                        AttackType.DDOS_UDP_FRAGMENTATION
                                    }
                                }
                            }
                        }
                    } else {
                        if (features.max <= 581.24f) {
                            AttackType.MIRAI_GREIP_FLOOD
                        } else {
                            if (features.max <= 592.25f) {
                                AttackType.MIRAI_GREETH_FLOOD
                            } else {
                                AttackType.MIRAI_GREIP_FLOOD
                            }
                        }
                    }
                }
            } else {
                if (features.rstCount <= 0.69f) {
                    if (features.synCount <= 1.11f) {
                        if (features.finCount <= 0.0f) {
                            if (features.min <= 57.58f) {
                                if (features.srate <= 0.0f) {
                                    AttackType.DDOS_SYNONYMOUS_IP_FLOOD
                                } else {
                                    if (features.srate <= 21.74f) {
                                        if (features.srate <= 3.09f) {
                                            AttackType.DDOS_SYN_FLOOD
                                        } else {
                                            AttackType.DDOS_SYN_FLOOD
                                        }
                                    } else {
                                        AttackType.DDOS_SYN_FLOOD
                                    }
                                }
                            } else {
                                AttackType.DDOS_SYN_FLOOD
                            }
                        } else {
                            if (features.totSize <= 55.58f) {
                                AttackType.DDOS_SYN_FLOOD
                            } else {
                                AttackType.DDOS_SYN_FLOOD
                            }
                        }
                    } else {
                        if (features.srate <= 0.53f) {
                            if (features.synCount <= 1.83f) {
                                AttackType.DDOS_SYNONYMOUS_IP_FLOOD
                            } else {
                                if (features.synCount <= 2.2f) {
                                    AttackType.DOS_SYN_FLOOD
                                } else {
                                    if (features.finCount <= 0.0f) {
                                        AttackType.DDOS_SYNONYMOUS_IP_FLOOD
                                    } else {
                                        AttackType.DOS_SYN_FLOOD
                                    }
                                }
                            }
                        } else {
                            if (features.rstCount <= 0.09f) {
                                if (features.totSize <= 54.07f) {
                                    AttackType.DDOS_SYNONYMOUS_IP_FLOOD
                                } else {
                                    AttackType.DDOS_SYNONYMOUS_IP_FLOOD
                                }
                            } else {
                                if (features.synCount <= 1.7f) {
                                    if (features.min <= 56.75f) {
                                        AttackType.DOS_SYN_FLOOD
                                    } else {
                                        AttackType.DDOS_SYN_FLOOD
                                    }
                                } else {
                                    AttackType.DOS_SYN_FLOOD
                                }
                            }
                        }
                    }
                } else {
                    if (features.urgCount <= 8.1f) {
                        if (features.avg <= 69.74f) {
                            if (features.synCount <= 0.91f) {
                                AttackType.RECON_HOST_DISCOVERY
                            } else {
                                if (features.number <= 7.28f) {
                                    AttackType.RECON_PORT_SCAN
                                } else {
                                    if (features.number <= 11.5f) {
                                        AttackType.DOS_SYN_FLOOD
                                    } else {
                                        AttackType.RECON_PORT_SCAN
                                    }
                                }
                            }
                        } else {
                            if (features.finCount <= 0.0f) {
                                if (features.number <= 11.5f) {
                                    if (features.number <= 6.92f) {
                                        AttackType.BENIGN_TRAFFIC
                                    } else {
                                        AttackType.DOS_SYN_FLOOD
                                    }
                                } else {
                                    AttackType.BENIGN_TRAFFIC
                                }
                            } else {
                                if (features.duration <= 72.65f) {
                                    AttackType.DOS_HTTP_FLOOD
                                } else {
                                    AttackType.RECON_HOST_DISCOVERY
                                }
                            }
                        }
                    } else {
                        if (features.rstCount <= 296.3f) {
                            if (features.ackCount <= 0.0f) {
                                AttackType.BENIGN_TRAFFIC
                            } else {
                                if (features.number <= 11.5f) {
                                    if (features.number <= 7.5f) {
                                        AttackType.BENIGN_TRAFFIC
                                    } else {
                                        AttackType.VULNERABILITY_SCAN
                                    }
                                } else {
                                    AttackType.BENIGN_TRAFFIC
                                }
                            }
                        } else {
                            AttackType.BENIGN_TRAFFIC
                        }
                    }
                }
            }
        }
    }
}
package com.reconx.sentinel.core.common

/**
 * A single assessment finding. Mirrors the ReconX backend finding shape so
 * results from the on-device engines and from the ReconX API can live in one
 * list. Severity and confidence are reported separately (spec §14).
 */
data class Finding(
    val id: String,
    val title: String,
    val category: String,
    val severity: Severity,
    val confidence: Confidence,
    val target: String,
    val evidence: Map<String, String> = emptyMap(),
    val explanation: String = "",
    val impact: String = "",
    val remediation: String = "",
    val verification: Verification = Verification.UNVERIFIED,
    val source: String = "sentinel",
    val timestampEpochMs: Long = System.currentTimeMillis(),
)

/** A neutral observation (asset/host/service), not itself a weakness. */
data class Observation(
    val kind: String,
    val value: String,
    val detail: Map<String, String> = emptyMap(),
    val confidence: Confidence = Confidence.FIRM,
    val source: String = "sentinel",
)

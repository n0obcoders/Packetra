package com.reconx.sentinel.feature.reporting

import com.reconx.sentinel.core.common.Finding

data class AssessmentReport(
    val engagementName: String,
    val clientLabel: String,
    val generatedAtEpochMs: Long,
    val scopeDomains: List<String>,
    val scopeCidrs: List<String>,
    val toolVersion: String,
    val findings: List<Finding>,
    val limitations: List<String> = emptyList(),
) {
    fun bySeverity() = findings.groupingBy { it.severity }.eachCount()
}

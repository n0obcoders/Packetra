package com.reconx.sentinel.core.storage

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "engagements")
data class EngagementEntity(
    @PrimaryKey val id: String,
    val name: String,
    val clientLabel: String,
    val status: String,            // DRAFT|PENDING_APPROVAL|APPROVED|CLOSED
    val domains: String,           // newline-joined
    val cidrs: String,             // newline-joined
    val exclusions: String,        // newline-joined
    val permittedModules: String,  // newline-joined module ids
    val requestsPerSecond: Double,
    val scanBudget: Int,
    val labConfirmed: Boolean,
    val notes: String,
    val createdAtEpochMs: Long,
)

@Entity(tableName = "findings")
data class FindingEntity(
    @PrimaryKey val id: String,
    val engagementId: String,
    val title: String,
    val category: String,
    val severity: String,
    val confidence: String,
    val target: String,
    val explanation: String,
    val remediation: String,
    val verification: String,
    val source: String,
    val evidenceJson: String,
    val timestampEpochMs: Long,
)

@Entity(tableName = "scan_tasks")
data class ScanTaskEntity(
    @PrimaryKey val id: String,
    val engagementId: String,
    val module: String,
    val classification: String,
    val targets: String,
    val status: String,            // queued|running|paused|done|cancelled|error
    val progress: Int,
    val startedAtEpochMs: Long,
    val finishedAtEpochMs: Long?,
    val scopeDecisionJson: String,
)

@Entity(tableName = "audit_events")
data class AuditEntity(
    @PrimaryKey(autoGenerate = true) val seq: Long = 0,
    val action: String,
    val actor: String,
    val engagementId: String?,
    val detail: String,
    val prevHash: String,
    val hash: String,
    val timestampEpochMs: Long,
)

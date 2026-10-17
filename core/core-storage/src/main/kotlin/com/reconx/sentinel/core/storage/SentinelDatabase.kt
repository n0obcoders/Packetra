package com.reconx.sentinel.core.storage

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [EngagementEntity::class, FindingEntity::class,
        ScanTaskEntity::class, AuditEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class SentinelDatabase : RoomDatabase() {
    abstract fun engagements(): EngagementDao
    abstract fun findings(): FindingDao
    abstract fun scanTasks(): ScanTaskDao
    abstract fun audit(): AuditDao
}

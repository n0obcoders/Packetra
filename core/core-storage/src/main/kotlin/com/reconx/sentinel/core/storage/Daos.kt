package com.reconx.sentinel.core.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao interface EngagementDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun upsert(e: EngagementEntity)
    @Query("SELECT * FROM engagements ORDER BY createdAtEpochMs DESC") fun observeAll(): Flow<List<EngagementEntity>>
    @Query("SELECT * FROM engagements WHERE id = :id") suspend fun byId(id: String): EngagementEntity?
}

@Dao interface FindingDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun upsertAll(items: List<FindingEntity>)
    @Query("SELECT * FROM findings WHERE engagementId = :eid ORDER BY timestampEpochMs DESC")
    fun observeForEngagement(eid: String): Flow<List<FindingEntity>>
    @Query("SELECT * FROM findings WHERE engagementId = :eid") suspend fun forEngagement(eid: String): List<FindingEntity>
}

@Dao interface ScanTaskDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun upsert(t: ScanTaskEntity)
    @Query("SELECT * FROM scan_tasks ORDER BY startedAtEpochMs DESC LIMIT :limit") fun recent(limit: Int): Flow<List<ScanTaskEntity>>
}

@Dao interface AuditDao {
    @Insert suspend fun insert(e: AuditEntity): Long
    @Query("SELECT * FROM audit_events ORDER BY seq DESC") suspend fun all(): List<AuditEntity>
    @Query("SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1") suspend fun last(): AuditEntity?
}

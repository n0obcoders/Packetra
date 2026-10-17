package com.reconx.sentinel.core.network

import kotlinx.coroutines.delay

/**
 * Token-free, time-based limiter: guarantees a minimum gap between operations
 * so every active engine honours a safe, configurable request rate (spec §5,
 * §16, §17 "safe default request rates"). Default 2 req/s matches the backend.
 */
class RateLimiter(requestsPerSecond: Double = 2.0) {
    private val minGapMs: Long = if (requestsPerSecond <= 0) 0 else (1000.0 / requestsPerSecond).toLong()
    @Volatile private var lastAt: Long = 0

    suspend fun acquire() {
        if (minGapMs == 0L) return
        val now = System.currentTimeMillis()
        val wait = (lastAt + minGapMs) - now
        if (wait > 0) delay(wait)
        lastAt = System.currentTimeMillis()
    }
}

/** Hard ceiling on total requests for one task run (spec §5 scan budget). */
class RequestBudget(private val max: Int) {
    private var used = 0
    @Synchronized fun tryConsume(): Boolean { if (used >= max) return false; used++; return true }
    @Synchronized fun remaining(): Int = (max - used).coerceAtLeast(0)
}

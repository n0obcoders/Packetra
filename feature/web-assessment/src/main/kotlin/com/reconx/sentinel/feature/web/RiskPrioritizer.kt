package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Verification

/**
 * Risk-based triage: groups/deduplicates findings and orders them by a CONTEXTUAL
 * priority rather than raw CVSS alone, so verified, high-confidence runtime issues
 * rise above theoretical or merely-informational ones. Pure and testable.
 *
 * Priority score folds together severity (the base weight), how sure we are the
 * finding is real (Confidence), and whether it was actively validated
 * (Verification) — a CONFIRMED/VALIDATED HIGH outranks a TENTATIVE/UNVERIFIED one
 * of the same severity. Buckets: P1 (critical, act now) … P4 (informational).
 */
object RiskPrioritizer {
    data class Group(
        val key: String,
        val representative: Finding,
        val count: Int,
        val targets: List<String>,
        val priority: Int,       // 1..4 (1 = highest)
        val score: Double,
    )

    private fun confidenceWeight(c: Confidence) = when (c) {
        Confidence.CONFIRMED -> 1.0
        Confidence.FIRM -> 0.8
        Confidence.TENTATIVE -> 0.55
    }

    private fun verificationWeight(v: Verification) = when (v) {
        Verification.CONFIRMED -> 1.0
        Verification.VALIDATED_SAFELY -> 0.85
        Verification.UNVERIFIED -> 0.6
    }

    /** Contextual score in roughly 0..10. */
    fun score(f: Finding): Double {
        val base = f.severity.rank * 2.5                       // 0 (INFO) .. 10 (CRITICAL)
        val factor = 0.5 + 0.5 * confidenceWeight(f.confidence) * verificationWeight(f.verification)
        return (base * factor).coerceIn(0.0, 10.0)
    }

    private fun bucket(score: Double): Int = when {
        score >= 8.0 -> 1
        score >= 5.0 -> 2
        score >= 2.5 -> 3
        else -> 4
    }

    /** Normalised grouping key: same issue type on the same logical target collapses. */
    private fun keyOf(f: Finding): String =
        (f.category + "|" + f.title.lowercase().replace(Regex("\\d+"), "#")).trim()

    /** Group + dedupe + order. Highest priority first; within a bucket, by score then count. */
    fun prioritize(findings: List<Finding>): List<Group> {
        val groups = LinkedHashMap<String, MutableList<Finding>>()
        for (f in findings) groups.getOrPut(keyOf(f)) { mutableListOf() }.add(f)
        return groups.map { (k, fs) ->
            val rep = fs.maxByOrNull { score(it) }!!
            val s = score(rep)
            Group(
                key = k, representative = rep, count = fs.size,
                targets = fs.map { it.target }.distinct(),
                priority = bucket(s), score = s,
            )
        }.sortedWith(compareBy<Group> { it.priority }.thenByDescending { it.score }.thenByDescending { it.count })
    }

    fun label(priority: Int) = when (priority) {
        1 -> "P1 — critical"
        2 -> "P2 — high"
        3 -> "P3 — medium"
        else -> "P4 — informational"
    }
}

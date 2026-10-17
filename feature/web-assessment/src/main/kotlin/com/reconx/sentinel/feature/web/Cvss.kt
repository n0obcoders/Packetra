package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity

/**
 * Indicative CVSS 3.1 base scoring for a finding. These are REPRESENTATIVE scores
 * mapped from the finding's category and severity so a report can show a CVSS
 * number and vector — they are a starting point for triage, not a substitute for
 * scoring each finding against its real environment. Labelled "indicative" in the
 * UI so no one mistakes it for an authoritative score.
 */
object Cvss {
    data class Score(val base: Double, val vector: String, val label: String)

    private fun label(base: Double): String = when {
        base == 0.0 -> "None"
        base < 4.0 -> "Low"
        base < 7.0 -> "Medium"
        base < 9.0 -> "High"
        else -> "Critical"
    }

    /** Representative CVSS 3.1 base vectors per category (network, low complexity). */
    fun forFinding(f: Finding): Score {
        val (base, vector) = when (f.category) {
            "access_control" -> when (f.severity) {
                Severity.HIGH, Severity.CRITICAL -> 8.1 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                else -> 5.3 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            }
            "injection" -> 9.8 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            "xss" -> 6.1 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
            "transport_security" -> when (f.severity) {
                Severity.HIGH, Severity.CRITICAL -> 7.4 to "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
                else -> 5.9 to "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
            }
            "session_security" -> 5.4 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
            "exposure", "information_disclosure" -> when (f.severity) {
                Severity.HIGH, Severity.CRITICAL -> 7.5 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                Severity.MEDIUM -> 5.3 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                else -> 3.1 to "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
            "misconfiguration" -> 5.3 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            else -> when (f.severity) {
                Severity.CRITICAL -> 9.1 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                Severity.HIGH -> 7.5 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                Severity.MEDIUM -> 5.3 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                Severity.LOW -> 3.1 to "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
                Severity.INFO -> 0.0 to "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
            }
        }
        return Score(base, vector, label(base))
    }
}

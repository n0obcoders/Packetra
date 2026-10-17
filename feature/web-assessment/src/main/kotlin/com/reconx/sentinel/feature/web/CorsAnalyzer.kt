package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Confidence
import com.reconx.sentinel.core.common.Finding
import com.reconx.sentinel.core.common.Severity
import com.reconx.sentinel.core.common.Verification

/**
 * Pure analysis of a CORS response. The caller sends ONE GET with a probe Origin
 * header (a benign, attacker-style origin) and passes the returned
 * Access-Control-Allow-Origin / Access-Control-Allow-Credentials values here.
 * This only reads the server's own CORS policy — it is not an attack.
 */
object CorsAnalyzer {
    /**
     * @param probeOrigin the Origin we sent (e.g. "https://evil.example").
     * @param acao  value of Access-Control-Allow-Origin in the response, or null.
     * @param acac  value of Access-Control-Allow-Credentials, or null.
     */
    fun analyze(url: String, probeOrigin: String, acao: String?, acac: String?): Finding? {
        if (acao == null) return null
        val reflectsArbitrary = acao.trim() == probeOrigin
        val wildcard = acao.trim() == "*"
        val creds = acac?.trim().equals("true", ignoreCase = true)

        val (title, sev, why) = when {
            reflectsArbitrary && creds -> Triple(
                "CORS reflects arbitrary origin with credentials", Severity.HIGH,
                "The server echoes any Origin in Access-Control-Allow-Origin and allows credentials, so a malicious " +
                    "site can read authenticated responses on behalf of a logged-in user.")
            reflectsArbitrary -> Triple(
                "CORS reflects arbitrary origin", Severity.MEDIUM,
                "The server echoes any Origin, so cross-origin sites can read non-credentialed responses.")
            wildcard && creds -> Triple(
                "CORS wildcard with credentials", Severity.HIGH,
                "Access-Control-Allow-Origin: * together with credentials is invalid and, where honored, exposes " +
                    "authenticated data.")
            else -> return null
        }
        return Finding(
            id = "web-cors-${url.hashCode().toUInt().toString(16)}",
            title = title, category = "access_control", severity = sev, confidence = Confidence.FIRM,
            target = url,
            evidence = mapOf("probeOrigin" to probeOrigin, "acao" to acao, "acac" to (acac ?: "")),
            explanation = why,
            remediation = "Allow only an explicit all-list of trusted origins; never reflect the Origin header, and " +
                "do not combine a wildcard or reflected origin with Allow-Credentials.",
            verification = Verification.VALIDATED_SAFELY, source = "web-assessment",
        )
    }
}

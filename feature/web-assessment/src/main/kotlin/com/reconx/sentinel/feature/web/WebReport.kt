package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.Finding

/** Structured result of a non-destructive web assessment, so the UI always has
 *  something concrete to show (status, server, TLS) even when there are no
 *  security findings — the previous screen looked "broken" when a redirect
 *  response carried no headers to flag. */
data class WebReport(
    val requestedUrl: String,
    val finalUrl: String,
    val status: Int,
    val statusLine: String,
    val server: String?,
    val https: Boolean,
    val title: String?,
    val redirectChain: List<String>,
    val tls: TlsInfo?,
    val findings: List<Finding>,
    val notes: List<String>,
    /** Controls verified present and correctly configured (the "passed" summary). */
    val passedChecks: List<PassedCheck> = emptyList(),
)

data class TlsInfo(
    val version: String,
    val cipher: String,
    val subject: String?,
    val issuer: String?,
    val notAfter: String?,
    val daysToExpiry: Long?,
    /** Subject Alternative Names from the leaf certificate — a passive source of
     *  sibling subdomains sharing the same certificate. */
    val sans: List<String> = emptyList(),
    /** Legacy protocol versions the server still negotiated (e.g. TLSv1, TLSv1.1). */
    val legacyProtocols: List<String> = emptyList(),
)

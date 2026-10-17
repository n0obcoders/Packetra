package com.reconx.sentinel.feature.recon

/** A discovered subdomain with its provenance and whether it was DNS-confirmed. */
data class Subdomain(
    val name: String,
    val source: String,          // e.g. "crt.sh", "dns"
    val resolved: Boolean = false,
    val addresses: List<String> = emptyList(),
    val discoveredAtEpochMs: Long = System.currentTimeMillis(),
)

data class ReconSummary(
    val domain: String,
    val subdomains: List<Subdomain>,
    val sources: Set<String>,
    val note: String = "",
)

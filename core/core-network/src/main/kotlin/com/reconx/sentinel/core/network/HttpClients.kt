package com.reconx.sentinel.core.network

import java.util.concurrent.TimeUnit
import okhttp3.ConnectionPool
import okhttp3.Dispatcher
import okhttp3.OkHttpClient

/**
 * Factory for OkHttp clients used by the recon/web engines.
 *
 * Performance: all engines share ONE base client, so they share a single
 * connection pool (keep-alive / HTTP/2 connection reuse) and one DNS cache.
 * Previously every call built a fresh client, discarding pooled connections and
 * re-resolving DNS each time. The redirect-on and redirect-off variants are
 * derived with newBuilder(), which keeps the shared pool, dispatcher and DNS.
 *
 * Safety: conservative timeouts, capped redirects (scope is re-checked on each
 * redirect hop by the caller), and a neutral, honest User-Agent that identifies
 * the tool. The dispatcher caps total in-flight requests so a large sweep stays
 * bounded rather than opening unlimited sockets.
 */
object HttpClients {
    const val USER_AGENT = "Packetra/1.0 (authorized-assessment)"

    /** Shared DNS cache so the same host is resolved once per window across engines. */
    val dns = CachingDns()

    private val pool = ConnectionPool(maxIdleConnections = 32, keepAliveDuration = 5, TimeUnit.MINUTES)

    private val base: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(12, TimeUnit.SECONDS)
        .callTimeout(20, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .connectionPool(pool)
        .dns(dns)
        .dispatcher(Dispatcher().apply {
            maxRequests = 64          // global bound on concurrent requests
            maxRequestsPerHost = 32   // per-host bound
        })
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private val noRedirect: OkHttpClient = base
    private val withRedirect: OkHttpClient = base.newBuilder()
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    /**
     * Longer-timeout client for passive OSINT aggregators (crt.sh especially can
     * take 20–40s to answer for a busy domain). Shares the base pool/DNS; follows
     * redirects since some sources 301 to a CDN.
     */
    private val osintClient: OkHttpClient = base.newBuilder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(40, TimeUnit.SECONDS)
        .callTimeout(55, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    /** Returns a shared client; variants share the base pool/dispatcher/DNS. */
    fun assessment(followRedirects: Boolean = false): OkHttpClient =
        if (followRedirects) withRedirect else noRedirect

    /** Shared client tuned for slow passive-OSINT endpoints. */
    fun osint(): OkHttpClient = osintClient
}

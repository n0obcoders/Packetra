package com.reconx.sentinel.feature.web

import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.network.HttpClients
import com.reconx.sentinel.core.security.ScopeValidator
import okhttp3.OkHttpClient
import okhttp3.Request
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/**
 * DirBuster-style content discovery, scope-gated and non-destructive (GET only).
 * Probes a base URL for paths from a wordlist, with soft-404 detection (a random
 * path establishes the "not found" fingerprint), status/size filtering and
 * concurrency control. No state-changing methods, no unbounded recursion.
 */
class DirectoryScanner(
    private val scope: ScopeValidator,
    private val dispatchers: DispatcherProvider,
    private val client: OkHttpClient = HttpClients.assessment(followRedirects = false),
) {
    data class Config(
        val baseUrl: String,
        val words: List<String>,
        val extensions: List<String> = emptyList(), // e.g. ["", "php", "bak"]
        val concurrency: Int = 24,
        val perRequestDelayMs: Long = 0,
        val hideStatuses: Set<Int> = setOf(404),
    )

    sealed interface Ev {
        data class Baseline(val softNotFoundLen: Long?, val total: Int) : Ev
        data class Hit(val path: String, val status: Int, val length: Long, val contentType: String?, val ms: Long) : Ev
        data class Progress(val done: Int, val total: Int, val hits: Int) : Ev
        data class Done(val done: Int, val hits: Int, val elapsedMs: Long) : Ev
        data class Failed(val reason: String) : Ev
    }

    fun scan(config: Config): Flow<Ev> = channelFlow {
        val base = config.baseUrl.trim().trimEnd('/')
        val decision = scope.validate(base)
        if (!decision.allowed) { send(Ev.Failed("refused: ${decision.reason}")); return@channelFlow }

        // Build the full candidate path list (word x extensions).
        val paths = buildList {
            for (w in config.words) {
                val word = w.trim().trimStart('/')
                if (word.isEmpty() || word.startsWith("#")) continue
                if (config.extensions.isEmpty()) add(word)
                else for (ext in config.extensions) add(if (ext.isBlank()) word else "$word.${ext.trimStart('.')}")
            }
        }.distinct()

        // Soft-404 baseline: a path that should not exist.
        val softLen = runCatching {
            request("$base/zz_nonexistent_${System.nanoTime().toString(36)}")?.second
        }.getOrNull()
        send(Ev.Baseline(softLen, paths.size))

        val started = System.currentTimeMillis()
        val gate = Semaphore(config.concurrency.coerceIn(1, 64))
        val results = Channel<Ev.Hit?>(Channel.UNLIMITED)

        coroutineScope {
            launch {
                for (p in paths) launch(dispatchers.io) {
                    gate.withPermit {
                        if (config.perRequestDelayMs > 0) delay(config.perRequestDelayMs)
                        val start = System.currentTimeMillis()
                        val r = runCatching { request("$base/$p") }.getOrNull()
                        if (r == null) { results.send(null); return@withPermit }
                        val (status, len, ctype) = Triple(r.first, r.second, r.third)
                        val isSoft = softLen != null && status == 200 && len == softLen
                        if (status in config.hideStatuses || isSoft) results.send(null)
                        else results.send(Ev.Hit(p, status, len, ctype, System.currentTimeMillis() - start))
                    }
                }
            }
            var done = 0; var hits = 0
            while (done < paths.size) {
                val r = results.receive(); done++
                if (r != null) { hits++; send(r) }
                if (done % 20 == 0 || done == paths.size) send(Ev.Progress(done, paths.size, hits))
            }
            results.close()
            send(Ev.Done(done, hits, System.currentTimeMillis() - started))
        }
    }

    /** Returns (status, contentLength, contentType) or null on error. GET only.
     *  Never downloads the full body: uses the Content-Length header when present,
     *  otherwise peeks a bounded prefix. This keeps memory/CPU flat across a large
     *  wordlist instead of pulling entire pages into memory per path. */
    private fun request(url: String): Triple<Int, Long, String?>? =
        client.newCall(Request.Builder().url(url).get()
            .header("User-Agent", HttpClients.USER_AGENT).build()).execute().use { resp ->
            val headerLen = resp.body?.contentLength()?.takeIf { it >= 0 }
            val len = headerLen ?: runCatching { resp.peekBody(MAX_PEEK_BYTES).contentLength() }.getOrDefault(0L)
            Triple(resp.code, len, resp.header("Content-Type"))
        }

    private companion object {
        const val MAX_PEEK_BYTES = 65_536L
    }
}

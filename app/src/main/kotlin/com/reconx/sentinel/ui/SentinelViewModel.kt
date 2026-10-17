package com.reconx.sentinel.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.security.EngagementStatus
import com.reconx.sentinel.core.security.ScopePolicy
import com.reconx.sentinel.core.security.ScopeValidator
import com.reconx.sentinel.di.SettingsRepository
import com.reconx.sentinel.feature.web.DirectoryScanner
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** In-memory engagement the operator configures on-device (name, scope, status).
 *  Active engines read [scopeValidator]; nothing runs out of scope. */
data class EngagementState(
    val name: String = "",
    val clientLabel: String = "",
    val status: EngagementStatus = EngagementStatus.DRAFT,
    val domains: List<String> = emptyList(),
    val cidrs: List<String> = emptyList(),
    val exclusions: List<String> = emptyList(),
    val labConfirmed: Boolean = true,
) {
    val hasScope get() = domains.isNotEmpty() || cidrs.isNotEmpty()
    fun policy() = ScopePolicy(
        version = 1, domains = domains.toSet(), cidrs = cidrs,
        exclusions = exclusions.toSet(), allowPrivateForLab = labConfirmed,
    )
}

@HiltViewModel
class SentinelViewModel @Inject constructor(
    val dispatchers: DispatcherProvider,
    val settings: SettingsRepository,
) : ViewModel() {

    // Per-screen UI state cache. The ViewModel outlives navigation (scoped to the
    // Activity via hiltViewModel at the root), so Compose state objects kept here
    // survive leaving and returning to a screen — inputs and results are retained
    // and a screen never asks for the same input twice. See rememberVm* in Common.kt.
    val uiCache = HashMap<String, Any?>()

    /** Launches work on the ViewModel scope so it keeps running after the user
     *  navigates away, letting screens run concurrently without interrupting. */
    fun vmLaunch(block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit): Job =
        viewModelScope.launch(block = block)

    // Restore the saved scope so targets survive an app restart (the capture data
    // itself is never persisted — only an exported PCAP keeps its packets).
    private val _engagement = MutableStateFlow(runCatching { settings.loadEngagement() }.getOrDefault(EngagementState()))
    val engagement: StateFlow<EngagementState> = _engagement.asStateFlow()

    fun scopeValidator(): ScopeValidator = ScopeValidator(_engagement.value.policy())

    fun updateEngagement(transform: (EngagementState) -> EngagementState) {
        val next = transform(_engagement.value)
        _engagement.value = next
        runCatching { settings.saveEngagement(next) }
    }

    fun approve() = updateEngagement { it.copy(status = EngagementStatus.APPROVED) }

    // ---- Background directory scan ---------------------------------------
    // Runs in viewModelScope (not the screen's composition scope) so it keeps
    // going when the user navigates away and never drives the UI thread. State
    // updates are throttled so a large wordlist can't flood recomposition.

    data class DirScanUi(
        val running: Boolean = false,
        val status: String = "",
        val progress: Float = 0f,
        val total: Int = 0,
        val done: Int = 0,
        val hits: List<String> = emptyList(),
    )

    private val _dirScan = MutableStateFlow(DirScanUi())
    val dirScan: StateFlow<DirScanUi> = _dirScan.asStateFlow()
    private var dirJob: Job? = null

    fun runDirectoryScan(config: DirectoryScanner.Config) {
        dirJob?.cancel()
        val hits = ArrayList<String>()
        _dirScan.value = DirScanUi(running = true, status = "Starting…", total = config.words.size)
        dirJob = viewModelScope.launch(dispatchers.default) {
            var lastPush = 0L
            fun push(force: Boolean, mutate: (DirScanUi) -> DirScanUi) {
                val now = System.currentTimeMillis()
                if (force || now - lastPush >= UI_THROTTLE_MS) { lastPush = now; _dirScan.value = mutate(_dirScan.value) }
            }
            try {
                DirectoryScanner(scopeValidator(), dispatchers).scan(config).collect { ev ->
                    when (ev) {
                        is DirectoryScanner.Ev.Baseline ->
                            push(true) { it.copy(total = ev.total, status = "Probing ${ev.total} paths…") }
                        is DirectoryScanner.Ev.Hit -> {
                            hits.add("${ev.status}  ${ev.length}b  /${ev.path}  ${ev.contentType ?: ""}")
                            // keep the on-screen list bounded; full set stays copyable via count
                            val shown = if (hits.size > MAX_SHOWN_HITS) hits.takeLast(MAX_SHOWN_HITS) else hits.toList()
                            push(false) { it.copy(hits = shown) }
                        }
                        is DirectoryScanner.Ev.Progress ->
                            push(false) { it.copy(done = ev.done, progress = ev.done.toFloat() / ev.total.coerceAtLeast(1),
                                status = "${ev.done}/${ev.total} · ${ev.hits} hits") }
                        is DirectoryScanner.Ev.Done ->
                            push(true) { it.copy(running = false, progress = 1f,
                                status = "Done: ${ev.hits} hits in ${ev.elapsedMs} ms",
                                hits = if (hits.size > MAX_SHOWN_HITS) hits.takeLast(MAX_SHOWN_HITS) else hits.toList()) }
                        is DirectoryScanner.Ev.Failed ->
                            push(true) { it.copy(running = false, status = ev.reason) }
                    }
                }
            } catch (ce: CancellationException) {
                _dirScan.value = _dirScan.value.copy(running = false, status = "Cancelled.")
                throw ce
            } catch (t: Throwable) {
                _dirScan.value = _dirScan.value.copy(running = false,
                    status = "Failed: ${t.message ?: t.javaClass.simpleName}")
            }
        }
    }

    fun cancelDirectoryScan() { dirJob?.cancel() }

    private companion object {
        const val UI_THROTTLE_MS = 120L
        const val MAX_SHOWN_HITS = 500
    }
}

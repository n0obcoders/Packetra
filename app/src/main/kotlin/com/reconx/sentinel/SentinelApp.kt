package com.reconx.sentinel

import android.app.Application
import com.reconx.sentinel.di.SettingsRepository
import com.reconx.sentinel.feature.capture.CaptureController
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class SentinelApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Restore saved proxy + firewall into the capture bridge before any capture
        // starts, so these settings persist across restarts. Captured packets are
        // never restored — a capture session is live-only by design.
        runCatching {
            val settings = SettingsRepository(this)
            CaptureController.setProxy(settings.loadProxy())
            CaptureController.setFirewall(settings.loadFirewall())
        }
    }
}

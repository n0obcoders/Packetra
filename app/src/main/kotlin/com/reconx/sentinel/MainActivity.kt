package com.reconx.sentinel

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.reconx.sentinel.ui.SentinelAppRoot
import com.reconx.sentinel.ui.theme.SentinelTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { SentinelTheme { SentinelAppRoot() } }
    }
}

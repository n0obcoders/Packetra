package com.reconx.sentinel.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = Color(0xFF38BDF8),
    secondary = Color(0xFF7DD3FC),
    background = Color(0xFF0A0F1A),
    surface = Color(0xFF111827),
    onBackground = Color(0xFFE6EDF3),
    onSurface = Color(0xFFE6EDF3),
)
private val LightColors = lightColorScheme(
    primary = Color(0xFF0369A1),
    secondary = Color(0xFF0284C7),
    background = Color(0xFFFFFFFF),
    surface = Color(0xFFF6F8FA),
)

@Composable
fun SentinelTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (dark) DarkColors else LightColors, content = content)
}

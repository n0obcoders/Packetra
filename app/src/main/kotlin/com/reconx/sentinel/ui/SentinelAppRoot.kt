package com.reconx.sentinel.ui

import android.content.Context
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.imePadding
import androidx.compose.material.icons.filled.Menu
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.reconx.sentinel.ui.nav.Dest
import com.reconx.sentinel.ui.screens.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SentinelAppRoot(vm: SentinelViewModel = hiltViewModel()) {
    val ctx = LocalContext.current
    // First-launch greeting, shown once. The flag is persisted so returning users
    // go straight to the app.
    val prefs = remember { ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE) }
    var welcomed by remember { mutableStateOf(prefs.getBoolean(KEY_WELCOMED, false)) }
    if (!welcomed) {
        WelcomeScreen(onGetStarted = {
            prefs.edit().putBoolean(KEY_WELCOMED, true).apply()
            welcomed = true
        })
        return
    }

    val nav = rememberNavController()
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val backStack by nav.currentBackStackEntryAsState()
    val current = backStack?.destination?.route ?: Dest.start.route
    val focus = LocalFocusManager.current
    // Opening the drawer must drop any text-field focus, otherwise the field's
    // selection handle (a small teardrop) renders in its own popup window and
    // floats on top of the drawer and other screens.
    LaunchedEffect(drawer.currentValue) {
        if (drawer.currentValue == DrawerValue.Open) focus.clearFocus(force = true)
    }

    ModalNavigationDrawer(
        drawerState = drawer,
        drawerContent = {
            ModalDrawerSheet {
                Text("Packetra", style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(16.dp))
                Dest.entries.forEach { d ->
                    NavigationDrawerItem(
                        icon = { Icon(d.icon, null) },
                        label = { Text(d.label) },
                        selected = current == d.route,
                        onClick = {
                            scope.launch { drawer.close() }
                            nav.navigate(d.route) { launchSingleTop = true }
                        },
                    )
                }
            }
        },
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(Dest.entries.first { it.route == current }.label) },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawer.open() } }) {
                            Icon(androidx.compose.material.icons.Icons.Filled.Menu, "Menu")
                        }
                    },
                )
            },
        ) { pad ->
            // imePadding() keeps the active input above the soft keyboard; paired
            // with android:windowSoftInputMode="adjustResize" in the manifest so an
            // editable field is never hidden behind the keyboard.
            Box(Modifier.padding(pad).imePadding()) {
                NavHost(nav, startDestination = Dest.start.route) {
                    composable(Dest.DASHBOARD.route) { DashboardScreen(vm, nav) }
                    composable(Dest.SUBDOMAINS.route) { SubdomainScreen(vm) }
                    composable(Dest.DIRECTORY.route) { DirectoryScreen(vm) }
                    composable(Dest.SCANNER.route) { ScannerScreen(vm) }
                    composable(Dest.PACKETS.route) { PacketScreen() }
                    composable(Dest.WEB.route) { WebScreen(vm) }
                    composable(Dest.AUTH.route) { AuthAuditScreen(vm) }
                    composable(Dest.REPORTS.route) { ReportsScreen(vm) }
                    composable(Dest.SETTINGS.route) { SettingsScreen(vm) }
                    composable(Dest.ABOUT.route) { AboutScreen() }
                }
            }
        }
    }
}

private const val PREFS = "packetra_prefs"
private const val KEY_WELCOMED = "welcomed_v1"

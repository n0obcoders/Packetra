package com.reconx.sentinel.ui.nav

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Insights
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector

/** The primary navigation destinations. */
enum class Dest(val route: String, val label: String, val icon: ImageVector) {
    DASHBOARD("dashboard", "Dashboard", Icons.Filled.Dashboard),
    SUBDOMAINS("subdomains", "Subdomain Discovery", Icons.Filled.AccountTree),
    DIRECTORY("directory", "Directory Discovery", Icons.Filled.FolderOpen),
    SCANNER("scanner", "Network Scanner", Icons.Filled.Lan),
    PACKETS("packets", "Packet Analyzer", Icons.Filled.Insights),
    WEB("web", "Web Assessment", Icons.Filled.Language),
    AUTH("auth", "Authentication Audit", Icons.Filled.Password),
    REPORTS("reports", "Reports", Icons.Filled.Description),
    SETTINGS("settings", "Settings", Icons.Filled.Settings),
    ABOUT("about", "About me", Icons.Filled.Person);

    companion object { val start = DASHBOARD }
}

package com.reconx.sentinel.feature.capture

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Best-effort attribution of a captured flow to the app that owns it.
 *
 * On Android 10+ (API 29) ConnectivityManager.getConnectionOwnerUid() returns
 * the UID that owns a (local, remote) socket pair from the kernel's connection
 * table; PackageManager then maps the UID to an application label. This is the
 * same public API a legitimate connection monitor uses — no root, no hidden
 * APIs — and it only ever reports the owner of a connection already visible on
 * this device. If the lookup fails (older OS, connection already closed, no
 * match) it returns null and the flow is simply shown without an app label.
 *
 * The local address is the TUN interface address the VpnService established,
 * since captured app sockets are routed through it.
 */
class AppAttributor(
    context: Context,
    private val localAddress: InetAddress,
) : (ConnKey) -> String? {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private val pm = context.packageManager
    private val labelCache = HashMap<Int, String>()

    override fun invoke(key: ConnKey): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        val mgr = cm ?: return null
        val proto = when (key.proto.uppercase()) {
            "TCP" -> IPPROTO_TCP
            "UDP" -> IPPROTO_UDP
            else -> return null
        }
        val local = InetSocketAddress(localAddress, key.srcPort)
        val remote = InetSocketAddress(runCatching { InetAddress.getByName(key.dstIp) }.getOrNull()
            ?: return null, key.dstPort)
        val uid = runCatching { mgr.getConnectionOwnerUid(proto, local, remote) }.getOrNull() ?: return null
        if (uid < 0 || uid == INVALID_UID) return null
        return labelFor(uid)
    }

    private fun labelFor(uid: Int): String? {
        labelCache[uid]?.let { return it }
        val label = when (uid) {
            0 -> "system (root)"
            Process.SYSTEM_UID -> "android system"
            else -> runCatching {
                // Try the uid directly, then the app-id within its user profile
                // (uid = userId*100000 + appId); isolated and secondary-user uids
                // don't resolve otherwise. QUERY_ALL_PACKAGES lets us see them.
                val first = pm.getPackagesForUid(uid)?.firstOrNull()
                    ?: pm.getPackagesForUid(uid % 100000)?.firstOrNull()
                if (first != null) {
                    val ai = pm.getApplicationInfo(first, 0)
                    pm.getApplicationLabel(ai).toString() + " ($first)"
                } else {
                    // getNameForUid often yields a package (or "pkg:uid") for shared
                    // uids; if it names a package, surface it so the row is openable.
                    val named = runCatching { pm.getNameForUid(uid) }.getOrNull()
                    val pkg = named?.substringBefore(':')?.takeIf { it.contains('.') }
                    if (pkg != null)
                        runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() + " ($pkg)" }
                            .getOrDefault("$pkg (uid $uid)")
                    else "uid $uid"
                }
            }.getOrDefault("uid $uid")
        }
        label?.let { labelCache[uid] = it }
        return label
    }

    private companion object {
        const val IPPROTO_TCP = 6
        const val IPPROTO_UDP = 17
        const val INVALID_UID = -1
    }
}

# Compatibility & honest status report

This document is the Phase-1 deliverable required by the spec: the Android feature
matrix, the ReconX module compatibility report, and an honest account of what was
built, what was verified, and what still requires a device or the Android toolchain.

## 1. Build-environment disclosure

This project was authored in a cloud container that has **JDK 21 and Gradle but
NO Android SDK, NO Android NDK, and NO Kotlin compiler**, and whose egress proxy
blocks `dl.google.com` (the Android Gradle Plugin repository). Consequently:

- **No APK (debug or release) was compiled here.**
- **No Kotlin was compiled and no on-device/unit test was executed here.**
- The Gradle wrapper (`gradlew` + `gradle-wrapper.jar`, Gradle 8.9) **is** included
  and valid, so the project builds on any machine with the SDK and network access.

What *was* verified in-container, honestly:

- **Scope/CIDR algorithm:** the exact logic of `Cidr` + `ScopeValidator` was ported
  to Java and run on JDK 21 against 20 cases (domain suffix, lookalike rejection,
  CIDR v4/v6, /32 host routes, private-network blocking + lab opt-in, metadata always
  denied, exclusion-overrides-include, URL/port stripping) — **20/20 passed**. The
  Kotlin uses the same `java.net.InetAddress`/`BigInteger` APIs.
- **XML well-formedness:** all 8 manifests/resources parse cleanly.
- **Structure:** 62 Kotlin files across 12 Gradle modules; imports and brace balance
  reviewed by hand (the one apparent imbalance is `}` inside a regex literal).

The matching Kotlin unit tests (JUnit + Truth) are included and are what the CI/
developer runs to confirm the same logic on the real toolchain — see TESTING.md.

## 2. Android feature matrix

| Capability (spec §) | On non-root Android? | This build |
|---|---|---|
| Passive subdomain discovery — CT logs (§7) | Yes | **Implemented** |
| DNS resolution / record checks (§7) | Yes | **Implemented** |
| TCP connect scanning (§5) | Yes (connect() only; no raw SYN) | **Implemented** |
| UDP service checks (§5) | Partial (no ICMP unreachable without root) | Not in this build |
| Web header/cookie/TLS review (§9) | Yes | **Implemented** |
| Report JSON/CSV/HTML (§14) | Yes | **Implemented** |
| Report PDF (§14) | Yes (Android print framework renders the HTML) | Hook documented, not wired |
| Auth **policy/config** review (§10) | Yes (offline logic) | **Implemented** |
| Controlled test-account check (§10) | Yes, against local/authorized test env | Caps + plan model implemented; network check not wired |
| Local VPN capture of device's own traffic (§4) | Yes (VpnService, user-consented) | **Partial** (see §4 below) |
| Live packet list + PCAP/PCAPNG export (§4) | Yes, with work | TODO (device validation) |
| Raw interface capture (§4) | Root only | Not bundled |
| PTY terminal + PRoot Linux userspace (§12) | Yes, with NDK + native layer | Scaffold only |
| Tool install via PRoot (§11) | Yes, with the userspace | Scaffold only |
| Attack-surface graph (§8) | Yes (UI) | Backed by recon data; graph UI not built |

### Why these Android limits are real, not excuses

- **No raw sockets / SYN scan without root.** Android denies `CAP_NET_RAW` to normal
  apps, so the portable technique is a full TCP `connect()` — which is exactly what
  `TcpConnectScanner` does. It is honest about `FILTERED` (no response) vs `CLOSED`.
- **VpnService sees only this device's traffic**, never other hosts', and cannot
  decrypt TLS/QUIC. The code and UI say so; it never claims to reveal passwords from
  encrypted captures.
- **Terminal/PRoot need native binaries** built with the NDK (a terminal emulator +
  a PRoot userspace). The NDK is absent here, so this build ships the UI and honest
  "needs device/NDK" messaging rather than a fake shell.

## 3. ReconX module compatibility report (spec §6)

The Android client drives the ReconX REST API; each ReconX module's *execution*
still happens where ReconX runs. Classification of the 23 registered ReconX modules:

**Native on Android via the client (passive / HTTP / DNS) — launch & render directly:**
`passive.cert_transparency`, `passive.dns_inventory`, `passive.asn_enrichment`,
`passive.email_security`, `passive.wayback`, `dns.subdomain_discovery`,
`web.http_inventory`, `web.api_discovery`, `tls.config`,
`vuln.cve_correlation`, `vuln.misconfiguration`, `vuln.dependency_audit` (offline
catalog/text), `source.secret_scan` / `source.iac_review` (offline text/manifest
review of supplied input).

> Several of these run as config/offline review in ReconX by design (documented in
> the ReconX README). The client surfaces that status; it does not inflate them.

**Best via the Linux userspace (PRoot) when present, else the remote ReconX host:**
`network.service_inventory` (prefers an `nmap` binary), `cloud.posture_review`,
`cloud.kubernetes_posture` (need cloud/k8s SDKs + credentials),
`containers` image metadata (needs an image/SBOM source).

**Require a remote execution environment / explicit opt-in (not on the phone):**
`advanced.threat_intel`, `advanced.blockchain`, `advanced.iot_ot` (external provider
credentials), `auth.oauth_oidc`, `auth.password_policy`, `auth.session_security`
(run against the authorized target from ReconX, with its safeguards),
`auth.lab`, `lab.fuzzing`, `lab.adversary_emulation` (disabled-by-default, triple-gated
lab modules — kept server-side under ReconX's isolation controls).

The in-app **ReconX** screen lists each module with its classification tag so the
operator sees before running whether it executes locally, needs the userspace, or
runs on the remote host.

## 4. Packet capture — exact partial status

Shipped and reviewed: `SentinelVpnService` (builds the TUN, read loop), `PacketParser`
(IPv4/IPv6 + TCP/UDP header parsing with malformed-packet safety; unit-tested logic),
`ConnectionTracker` (per-flow byte aggregation; unit-tested).

Not yet done (needs an emulator/device to validate, and is labelled as such in the
Packet Analyzer screen):

1. **Packet reinjection** — writing packets back out so the device keeps
   connectivity while capturing. The read loop has an explicit TODO where this goes.
2. **PCAP/PCAPNG serialisation** and import.
3. **Foreground-service notification** lifecycle and the VPN consent `prepare()` flow
   from the UI (the manifest service + permissions are in place).

These are deliberately left as honest TODOs rather than shipped as a fake capture.

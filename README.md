# Packetra

**Packetra** is an authorized, **defensive-first** Android network-visibility and
security-assessment toolkit. It **detects, inspects and reports** — it captures
*your own device's* traffic, maps every connection to its app, geography and
network, and audits the security posture of systems you own or are explicitly
permitted to assess. It is **not** an attack toolkit.

> **Authorized use only.** Every *active* check is gated behind an engagement
> scope with **deny-by-default** validation, is non-destructive (GET-only, no
> write methods), and is bounded by conservative concurrency. There is no
> exploitation, payload/shell generation, brute-forcing, credential harvesting,
> lateral movement, **TLS decryption**, or data exfiltration anywhere in this
> codebase. Packet capture is limited to **this device's own traffic**.

- **Platform:** Android (Kotlin 2.0.20, Jetpack Compose, Hilt, Room)
- **applicationId** `com.packetra.nitin` · **minSdk** 26 (Android 8.0) · **compile/target** 34 · AGP 8.5.2 · Gradle 8.9 · JDK 17+
- **Current build:** versionName `1.19.0` (versionCode 21)
- **Author:** Nitin Shukla — [github.com/n0obcoders](https://github.com/n0obcoders) · [portfolio](https://n0obcoders.github.io/portfoli0)

---

## Highlights in this build

- ⚡ **High-throughput capture, no UI lag — now including the proxy path.** The
  flow tracker updates counters **in place** (no per-packet allocation), the
  capture service re-publishes the view **only when something changed** and caps
  what the list renders, every on-screen list is a **lazy list**, SNI/HTTP is
  parsed **only until a flow's host is known** (not on every packet of a bulk
  transfer), and when an **upstream proxy** is used, device→remote bytes are
  written by a **per-connection writer thread** so a slow/backpressured proxy can
  never stall capture.
- ▶️ **Runs in the background.** Capture is a foreground service that keeps
  running when you leave the app or swipe it from recents — only the in-app Stop
  button (or revoking the VPN) ends it.
- 💾 **Remembers your setup.** Your **scope/targets, proxy and firewall** persist
  across restarts. The **captured packets themselves are session-only** by design
  — only an **exported PCAP** keeps its data.
- 🔎 **Combined connection filter.** One control filters live connections by
  **IP, host, app name or port**, with a **TCP / UDP / All** transport toggle.
- 📦 **Readable packets + n3-editor.** Every connection shows the first request
  and response bytes as **hex + ASCII + text**, and every capture is written to a
  **PCAPng** you can export. Open the export in
  [**n3-editor**](https://github.com/n0obcoders/n3-editor) — an advanced pcap-reader notepad —
  to read every packet and what it contains. After a capture records packets, a
  brief in-app prompt points you to it.
- 📱 **Open the owning app in one tap** — launches the app, or opens its App-info
  screen, or the system Apps settings as a guaranteed fallback.
- 🎨 Rebranded as **Packetra** with a radar-rings logo, a first-launch welcome
  screen, and an **About** page.

---

## What it does

### 1. Packet Analyzer (own-device only)
A non-root `VpnService` that captures **this device's own IPv4 traffic** — no root,
no MITM, **no TLS/HTTPS decryption**.

- Flow-level tracking with **app attribution**, offline **ASN / network org +
  country** (name + flag), TLS **SNI** and cleartext **HTTP host** extraction
  (metadata only).
- **Protocol classification (DPI)** — identifies TLS / HTTP / DNS / QUIC / SSH / …
  from the first bytes + port, and flags whether a flow is encrypted.
- **Carried-content type on cleartext** — magic-byte + HTTP `Content-Type`
  detection labels what a *readable* flow carries (image / video / audio / PDF /
  text / archive). Encrypted flows are shown as encrypted, never guessed.
- **Combined filter** — filter the live list by IP / host / app / port and by
  transport (TCP / UDP / All) in one place.
- **Payload view on tap** — offset / hex / ASCII dump plus a readable-text extract
  of the first request *and* first response bytes, all copyable. These are the raw
  bytes seen on the TUN (the same data PCAP writes); an encrypted flow therefore
  shows ciphertext — honest about what is and isn't readable.
- **Open the owning app** — tap the launch icon to open the app, its App-info
  screen, or (when the owner can't be resolved) the system Apps settings.
- On-device **firewall** with **per-app transport choice (TCP / UDP / both)**,
  domain and IP rules, plus a malware/tracker blocklist.
- **Upstream proxy (SOCKS5 / HTTP CONNECT)** — optionally route captured TCP
  through your own proxy/VPN while still capturing. Routing only; nothing is
  decrypted; UDP stays direct so DNS/QUIC keep working.
- Export to **PCAPng**, **PCAP-over-IP** (live to Wireshark), and **HAR**.

### 2. Web Assessment (non-destructive)
Passive-leaning configuration review plus lightweight, single-probe signal checks:
security headers, CSP analysis, cookie-security audit, CORS, cache-control,
TLS telemetry (version/issuer/expiry/SANs, deprecated TLS, weak ciphers),
redirect-chain validation, multi-path sampling, essential-files checks,
technology fingerprinting with an offline EOL table, client-side asset & secret
scanning (every match redacted), and inert injection *signals* (never exploits).
Reporting with indicative CVSS 3.1, P1–P4 triage, and export to **JSON / SARIF
2.1.0 / Markdown** with per-finding fix snippets.

### 3. Reconnaissance (passive OSINT)
Certificate Transparency + passive subdomain enumeration (crt.sh, certspotter,
hackertarget, OTX, rapiddns, urlscan, wayback, subdomain.center), DoH DNS records,
RDAP/WHOIS, email posture (SPF/DMARC/DKIM/DNSSEC), subdomain-takeover
fingerprinting (passive CNAME→service match), and per-host scan drift tracking.

### 4. Network Discovery
Non-root, scope-gated TCP-connect scanner (`java.net.Socket`), nmap-style command
parser (never shelled out), bounded concurrency.

### 5. Auth Audit & Reporting
Offline password-policy / configuration review (no attacks) and JSON/CSV/HTML
report rendering via `FileProvider`.

---

## Safety model

- **ScopeValidator is deny-by-default** for every active engine. Cloud metadata
  endpoints and SSRF-range targets are always blocked; exclusions are honored.
- Active web checks are **GET-only**. No fuzzing, no write methods.
- Packet capture is limited to the device's own traffic and **never decrypts TLS**.
- Secret-scanner matches are **redacted** before display or export.
- Bounded concurrency (`Semaphore`) on every fan-out.
- Least-privilege manifest; `allowBackup` off; no contacts/SMS/location/accessibility.

See [SECURITY.md](SECURITY.md) for the full model and the explicit list of things
the tool will not do.

---

## Modules

```
app                         Compose UI, navigation, ViewModel, Hilt DI, VpnService hookup
core/core-common            Finding / Severity / Confidence model, dispatchers
core/core-security          ScopeValidator (deny-by-default), CIDR, redaction   ← safety core
core/core-network           Shared OkHttp clients, caching DNS
core/core-storage           Room entities / DAOs + DataStore
feature/packet-capture      Non-root VpnService capture, flow tracking, DPI, firewall, PCAP
feature/web-assessment      Header/CSP/cookie/TLS/CORS review, reporting
feature/reconnaissance      Passive OSINT, CT logs, DNS, email posture
feature/network-discovery   Scope-gated TCP-connect scanner
feature/auth-audit          Offline password-policy / config review
feature/reporting           JSON/CSV/HTML report rendering
```

---



## About the author

Built by **Nitin Shukla**.

- GitHub: [github.com/n0obcoders](https://github.com/n0obcoders)
- Project repo: [github.com/n0obcoders/packetra](https://github.com/n0obcoders/packetra)
- Portfolio: [n0obcoders.github.io/portfoli0](https://n0obcoders.github.io/portfoli0)

---

## License

See [LICENSE](LICENSE). Use Packetra only against systems you own or are explicitly
authorized to assess — you are responsible for staying within your authorization.

# Packetra — v1.17.0 changes

This release implements the requested fixes/features. It stays within the app's
defensive, no-MITM design: **there is still no TLS/HTTPS decryption and no
man-in-the-middle** — the "see inside a packet" and "content type" features read
only cleartext, and the proxy feature is pure routing.

## 1. Results are now copyable (the "result not working" fix)
- `ui/screens/Common.kt` — `ScreenColumn` is wrapped in a `SelectionContainer`,
  so **every result on every screen** (Web Assessment findings, DNS/WHOIS, TLS,
  subdomains, triage, hashes, etc.) can be long-pressed and copied. Editable text
  fields inside are unaffected and keep working.
- `ui/screens/PacketScreen.kt` — the packet tabs and the connection-detail dialog
  are also wrapped, and payloads have explicit **Copy** buttons.

## 2. Location in packet capture
- New `CountryNames.kt` maps the offline country code to a readable name + flag.
- `ConnectionFlow` now carries the network **org** (e.g. "Cloudflare"); the
  Connections list and detail show `Network` and `Location (United States 🇺🇸)`.

## 3. Upstream proxy while capturing (SOCKS5 / HTTP CONNECT)
- New `ProxyConfig.kt` (config + pure, unit-tested SOCKS5/HTTP-CONNECT handshake).
- `TcpForwarder` routes captured **TCP** through the proxy when enabled; UDP stays
  direct so DNS/QUIC keep working. New **Proxy** tab in the Packet screen.
- Routing only — your encrypted bytes stay encrypted through the proxy.

## 4. See what a packet contains
- Connection detail shows a hex+ASCII dump **and** a readable-text extract of the
  first request and first **response** payloads (response sampling is new), capped
  at 1 KB each. Encrypted flows honestly show ciphertext.

## 5. uid → openable app
- `AppAttributor` resolves more uids (adds a `getNameForUid` fallback).
- Apps/connection rows have an **Open app** action: launches the app, or opens its
  App-info screen when it has no launcher; works even for bare-uid flows.

## 6. Firewall: TCP / UDP / both, multiple apps
- `FirewallRules` app rules now carry a transport selector (`Proto.TCP/UDP/BOTH`).
- Firewall tab has a default-transport chooser; per-app override via a suffix,
  e.g. `youtube:udp`, `dropbox:tcp`. Multiple apps = one per line (already worked).

## 7. Content type (image / text / video / pdf …) + Deep Packet Inspection
- New `ContentTypeDetector.kt` — magic-byte + HTTP `Content-Type` detection on
  **cleartext** (JPEG/PNG/GIF/WebP/MP4/WebM/MP3/Ogg/PDF/ZIP/gzip/text/HTML/JSON…).
- New `DpiClassifier.kt` — identifies TLS/HTTP/DNS/QUIC/SSH/DoT/NTP from the first
  bytes + port and flags encryption. Both are surfaced per connection.

## Decryption / "bypass encryption" — intentionally NOT added
Properly-encrypted TLS/QUIC cannot be read from a passive capture, and this app is
designed as a no-MITM tool. To inspect your **own** HTTPS for debugging, use a
consensual TLS-intercepting proxy with a CA you install on your own device
(e.g. mitmproxy, or PCAPdroid's mitm add-on) — a separate tool, by design.

## Tests
New/updated JVM unit tests in `feature/packet-capture/src/test/...`:
`InspectionTest.kt` (content-type, DPI, proxy wire format, country names, tracker
classify) and the per-protocol firewall cases in `PacketAdvancedTest.kt`.
Run with `./gradlew test`.

## Build
Open in Android Studio and run `:app`, or `./gradlew :app:assembleDebug`
(an Android SDK with platform/build-tools 34 is required). versionName bumped to
1.17.0 (versionCode 19).

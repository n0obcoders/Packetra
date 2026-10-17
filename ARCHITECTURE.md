# Architecture

## Goals

- **Authorized, defensive-first.** One authorization/scope service that every active
  engine must pass through — the same contract the ReconX backend enforces.
- **Honest capability boundaries.** Each engine reports exactly what it observed and
  what it could not do (Android non-root limits, encrypted payloads, unverified DNS).
- **Modular.** Every engine is a Gradle module that can be built, tested and disabled
  independently. The UI depends on engines; engines never depend on the UI.

## Layering

```
          ┌───────────────────────────────────────────────┐
  app     │  Compose UI · Navigation · Hilt · ViewModels   │
          │  SentinelVpnService hookup                     │
          └───────────────┬───────────────────────────────┘
                          │ depends on
  feature/  reconx-integration · network-discovery · reconnaissance ·
            web-assessment · packet-capture · auth-audit · reporting
                          │ depends on
  core/     core-common · core-security · core-network · core-storage
```

- **No upward dependencies.** `core-*` know nothing about features; features know
  nothing about `app`. This keeps the safety core (`core-security`) tiny, pure-JVM
  and unit-testable with no Android or network dependency.
- **MVVM.** `SentinelViewModel` holds the engagement/scope state and hands engines a
  freshly-built `ScopeValidator`. Screens are stateless Composables driven by state.
- **Coroutines + Flow.** Scans stream results back as `Flow<Outcome<…>>`; the UI
  collects them. `DispatcherProvider` is injected so engine logic is testable.

## The safety core (`core-security`)

Everything active funnels through two classes:

- **`ScopeValidator`** — deny-by-default target validation. Order: (1) metadata
  endpoints always denied, (2) private/loopback/link-local denied unless an explicit
  lab opt-in, (3) exclusions win, (4) a target must match an include rule (domain
  suffix or CIDR). DNS resolution is injectable so demo/lab runs use a synthetic
  resolver and tests are deterministic. This mirrors the ReconX backend's scope
  firewall so the two enforce the same boundary.
- **`AuthorizationService`** — RBAC + engagement-approval + lab-confirmation gate.
  Active modules require an **approved** engagement; lab modules require explicit
  confirmation.

`Redactor` strips tokens/passwords/keys from anything logged, stored, or reported.

## Data model

`core-common` defines `Finding` (with **severity and confidence reported
separately**, plus a `Verification` state) and `Observation`. On-device engines and
the ReconX API both normalise into `Finding`, so one report can combine both.
`core-storage` persists engagements, findings, scan tasks and an append-only,
hash-chained audit log via Room.

## ReconX integration (client/launcher)

The app does **not** reimplement ReconX. `feature/reconx-integration` is a Retrofit
client for the existing FastAPI platform (`/api/v1`): login → list plugins → create
scope-validated tasks → poll status → pull findings. The backend remains the
authority on scope approval, RBAC, rate/budget and audit; the app is a mobile
console that drives it and renders results. See [COMPATIBILITY.md](COMPATIBILITY.md)
for which ReconX modules run natively on Android, which need the Linux userspace,
and which require a remote host.

## Capture architecture (non-root)

`SentinelVpnService` uses Android's `VpnService` to receive the **device's own**
outbound IP packets on a local TUN. `PacketParser` reads IPv4/IPv6 + TCP/UDP headers
(returning null on malformed input), and `ConnectionTracker` aggregates per-flow
metadata and byte counts. This is explicitly VPN-based capture of local traffic, not
raw physical-interface capture, and HTTPS/QUIC payloads stay encrypted. Packet
reinjection (to preserve connectivity during capture) and PCAP/PCAPNG serialisation
are the remaining device-validation work (see COMPATIBILITY.md).

## Extensibility

A new engine is a new `feature/*` module that: takes a `ScopeValidator` + a
`DispatcherProvider`, returns `Outcome`/`Finding`, honours a `RateLimiter`, and gets
a screen wired into the nav graph. No change to `app` internals or other engines is
required — matching the spec's "stable module API" requirement.

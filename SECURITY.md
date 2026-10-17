# Security model & scope of use

Packetra is for **authorized** security assessment only: systems you own,
a controlled lab, a CTF range, or an engagement with documented written
authorization. Using it against systems you are not authorized to test may be
illegal. You are responsible for staying within your authorization.

## What the tool will not do

There is **no code anywhere in this project** for, and it must never be extended to add:

- credential stuffing, password spraying, or brute force against real accounts
- CAPTCHA or MFA bypass
- account-takeover workflows
- proxy rotation or other detection **evasion**
- covert monitoring of a person or device, or capturing another device's traffic
- silent privilege escalation, root exploitation, or disabling Android security
- destructive requests, data exfiltration, or uncontrolled fuzzing

The authentication module performs **policy and configuration review** and, at most,
a tightly-capped check of a **single operator-supplied test credential** against a
**local or explicitly-authorized test environment** (≤3 attempts, ≤1 account, ≤1
req/s, bounded duration). It is a verification aid, not an attack tool.

## Controls built in

- **Deny-by-default scope.** `ScopeValidator` refuses any target that doesn't match
  an authorized domain/CIDR. Private/loopback/link-local addresses are blocked unless
  an engagement is explicitly marked a confirmed isolated lab. Cloud **metadata
  endpoints are always refused**, even inside an allowed range.
- **Engagement approval gate.** Active modules run only when an engagement is
  **approved** and the module is permitted for it (`AuthorizationService`), mirroring
  the ReconX backend's RBAC + approval gates.
- **Rate limiting & budgets.** `RateLimiter` (default 2 req/s) and `RequestBudget`
  cap request rate and total requests per run. Auth checks are capped at ≤1 req/s.
- **Non-destructive by construction.** Web assessment sends one `GET` per target,
  does not auto-follow redirects (so an in-scope URL can't bounce to an out-of-scope
  host), and uses no write methods or fuzzing.
- **Honest capture.** VPN capture is the device's own traffic only; HTTPS/QUIC stays
  encrypted; TLS is never silently intercepted and no CA is installed without consent.
- **Credential & secret redaction.** `Redactor` strips bearer tokens, passwords, API
  keys, JWTs and AWS keys from logs, stored data and reports. Real passwords are never
  written to logs/reports; only a redacted descriptor (`<set:N chars>`) is kept.
- **Auditability.** `core-storage` keeps an append-only, hash-chained audit log of
  engagements, approvals and scan tasks.
- **Least privilege.** The manifest requests only `INTERNET`, `ACCESS_NETWORK_STATE`,
  foreground-service + notifications (for user-consented capture). `allowBackup` is
  off. No contacts, SMS, location, or accessibility permissions.

## Data handling

- Engagement data, findings and audit records are stored locally (Room/DataStore).
- The only outbound traffic is: the assessment requests you initiate against in-scope
  targets, Certificate-Transparency queries to the CT endpoint you configure, and
  calls to **your own** ReconX instance (URL you set in Settings). There is no
  bundled remote backend and no telemetry phone-home.
- Reports are generated on-device; sharing them is an explicit user action.

## Reporting a problem

If you find a way the tool could be misused beyond its intended authorized-assessment
purpose, or a control that can be bypassed, treat it as a security bug and fix the
control (or remove the capability) before use.

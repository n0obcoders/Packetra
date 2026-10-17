# Testing

## What exists

JVM unit tests (JUnit4 + Google Truth) ship for the pure-logic engines, which are
the safety-critical and most testable parts:

| Suite | Module | Covers |
|-------|--------|--------|
| `ScopeValidatorTest` | core-security | domain suffix, lookalike rejection, CIDR, private-block + lab opt-in, metadata-always-denied, exclusion-overrides-include, URL/port stripping |
| `CidrTest` | core-security | IPv4/IPv6 containment, /32 host routes, malformed input, v4-rule-vs-v6-addr |
| `RedactorTest` | core-security | bearer/password/JWT redaction, secret never echoed |
| `AuthorizationServiceTest` | core-security | approval gate, RBAC, permitted-module, lab confirmation, passive-on-draft |
| `PortModelTest` | network-discovery | well-known port labels, profile port sets, open-port filter |
| `ReconModelsTest` | reconnaissance | source attribution, summary aggregation |
| `HeaderAnalyzerTest` | web-assessment | missing HSTS, clean headers, info disclosure, plaintext HTTP, cookie redaction |
| `AuthAuditTest` | auth-audit | weak vs strong policy, test-plan authorization gate, caps enforced |
| `ReportRendererTest` | reporting | JSON/CSV/HTML output, severity sort, secret redaction in output |
| `PacketParserTest` | packet-capture | IPv4 TCP 5-tuple parse, short-packet null, flow byte aggregation |

Run them all:

```bash
./gradlew test
```

## What was verified in the authoring container (no Android toolchain)

Because the authoring container had no Android SDK/NDK and no Kotlin compiler, the
Kotlin was **not** compiled and these tests were **not** executed there. To avoid
claiming unverified behaviour, the core scope/CIDR **algorithm** was re-implemented
in Java (same `java.net`/`BigInteger` APIs the Kotlin uses) and executed on JDK 21
against the same 20-case matrix as `ScopeValidatorTest` + `CidrTest`:

```
RESULT: 20 passed, 0 failed
```

All 8 XML manifests/resources were validated as well-formed. See COMPATIBILITY.md §1.

## Integration / device testing (requires emulator or device — not yet executed)

Per spec §18, the following need a device/emulator and are **not** run in this build:

- VpnService startup/shutdown, capture, and PCAP export (capture layer is partial —
  see COMPATIBILITY.md §4).
- TCP connect scanning against an **isolated lab** target.
- CT subdomain discovery against a controlled test domain.
- Web checks against an intentionally-vulnerable local app (e.g. a lab juice-shop).
- Auth policy audit against a local mock-login environment.
- ReconX module execution against a running ReconX instance.

These are documented as device-validation TODOs rather than asserted as passing.

## Recommended manual smoke test (once built on a device)

1. Create + approve an engagement scoped to a lab domain/CIDR you control.
2. Reconnaissance → discover subdomains of the lab domain.
3. Network Scanner → `COMMON` profile against the lab host; confirm out-of-scope
   hosts are refused.
4. Web Assessment → a lab URL; confirm header findings render and cookies are redacted.
5. Reports → generate JSON; confirm no secret appears.

# auth-audit module scope

This module performs **authentication POLICY and CONFIGURATION verification only**,
for systems the operator owns or is explicitly authorized to test (spec §10).

It DOES:
- evaluate a declared/observed password policy against NIST-style guidance
- review session-cookie and session-expiry configuration
- document lockout / rate-limit policy and MFA workflow for the report
- support a dedicated local test-account / mock-login workflow with hard caps

It DELIBERATELY DOES NOT, and contains no code for:
- credential stuffing, password spraying, or brute force against real accounts
- CAPTCHA or MFA bypass, proxy rotation / evasion, or account takeover
- automated attempts against any account without explicit authorization

There is no "attack" execution path in this module. The only automated check is
verification of a single, operator-provided *test* credential against a local or
explicitly-authorized test environment, bounded by the controls below.

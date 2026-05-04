# Lessons Learned — sunlit-masvs Milestone 1

## What changed
- Created `secure_network` crate with TLS policy validation, certificate pinning, and cleartext traffic detection
- Added `TlsViolation`, `CertPinFailure`, `CleartextBlocked` variants to `security_events::EventKind`
- 50 new tests (14 TLS policy, 13 cert pin, 15 cleartext, 4 unit, 4 E2E)

## Design decisions and why
- Pure Rust policy objects — no TLS handshakes or platform SDK imports. Consuming app provides raw cert chains/TLS params. This keeps the crate portable across mobile platforms.
- `validate_der_at(cert_der, now)` accepts a time parameter — enables deterministic expiry testing without needing actually-expired certificates.
- `CleartextDetector` with localhost exemption list — mirrors Android `NetworkSecurityConfig` cleartext-traffic-permitted pattern for development convenience.
- `PinSet` uses SHA-256 of SPKI (Subject Public Key Info) — matches industry standard (RFC 7469 HPKP, Android Network Security Config).

## Mistakes made
- Initially tried to split IPv6 addresses on `:` for localhost detection — `[::1]:443` was incorrectly parsed. Fixed with bracket-aware parsing.
- First hex hash in tests was 68 chars (34 bytes) instead of 64 chars (32 bytes) for SHA-256.
- `time::OffsetDateTime` resolved to x509-parser's private re-export instead of the `time` crate. Required `::time::OffsetDateTime` syntax.

## Root causes
- IPv6 address format not considered in initial `is_localhost()` implementation. IPv6 bracket notation (`[::1]`) needs explicit handling.
- x509-parser re-exports the `time` crate, shadowing the external crate in dependent code.

## What was harder than expected
- Generating expired test certificates without the Python `cryptography` library or OpenSSL options supporting zero-day validity. Solved with the `validate_der_at()` time-injection pattern.
- The x509-parser `time` crate shadowing was unexpected and not documented in x509-parser's docs.

## Naming conventions established
- Crate: `secure_network` (matches workspace `secure_*` pattern)
- Test files: `crates/secure_network/tests/{tls_policy,cert_pin,cleartext}_tests.rs`
- E2E file: `crates/secure_network/tests/e2e_sunlit_masvs_m1.rs`
- EventKind variants: `TlsViolation`, `CertPinFailure`, `CleartextBlocked` (PascalCase, descriptive)
- Error enum: `NetworkSecurityError` (crate-prefixed, `#[non_exhaustive]`)

## Test patterns that worked well
- BDD-style test names: `given_*_when_*_then_*` pattern matches runbook scenario tables directly
- `InMemorySink` from `security_events` for capturing emitted events in tests
- Time-injection via `validate_der_at()` for deterministic cert expiry tests
- Test certificate generated with openssl and stored as DER in `tests/testdata/`

## Missing tests that should exist now
- Property tests for `PinSet` with random SHA-256 hashes (fuzz target deferred to M9)
- Fuzz target for `CleartextDetector` with arbitrary URLs (deferred to M9)
- Integration test with multi-cert chain validation (partially covered by E2E)

## Rules for the next milestone
- Always use `::time::OffsetDateTime` in crates that depend on x509-parser (or any crate that re-exports `time`)
- Test IPv6 addresses explicitly in any URL/host parsing code
- Verify hex string lengths match expected hash output sizes in test data
- Use time-injection patterns for any time-dependent validation (don't rely on generating expired artifacts)

## Template improvements suggested
- The runbook E2E runtime validation table references `cargo test -p secure_smoke_service --test '*'` but M1 E2E tests live in `secure_network`, not `secure_smoke_service`. The smoke service routes are added in M8. Consider clarifying that pre-M8 milestones run E2E from their own crate.

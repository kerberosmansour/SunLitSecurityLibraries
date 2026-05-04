# Lessons Learned — sunlit-masvs Milestone 9

## What changed
- Added 10 new fuzz targets across 6 crates (secure_network, secure_boundary, secure_resilience, secure_privacy, secure_data, security_events)
- Added 17 property-based tests across 4 crates using proptest with 1000 cases each
- Added 57 CVE regression tests across 7 test files covering MASWE-0001, -0050, -0052, -0058, -0069, -0097, -0109
- Added `proptest = "1"` dev-dependency to secure_network, secure_resilience, secure_privacy

## Design decisions and why
- Property tests use 1000 cases per property (runbook requires minimum 1000) — balances thoroughness with test speed
- CVE regression tests are plain `#[test]` functions (not proptest) — deterministic reproducibility for known vulnerability patterns
- Feature-gated tests (`#![cfg(feature = "mobile-platform")]`) follow existing pattern in `platform_tests.rs` — ensures consistency with crate API visibility
- Fuzz directories remain separate Cargo workspaces — matches existing pattern and avoids polluting main workspace

## Mistakes made
- Used `prop_assert_eq!` with inline format variable captures (`{variable}`) which are not supported by `format_args!` — caused compilation errors
- Used `EventKind::AccessDenied` which doesn't exist — correct variant is `EventKind::AuthzDeny`
- Used `String` after passing to `prop_assert_ne!` which moves the value — needed `.clone()` before the assertion
- Used `admin@192.168.1.1` as an email test input — PII classifier email regex requires TLD of 2+ characters, so IP-like domains don't match as emails

## Root causes
- proptest assertion macros expand through `format_args!` which has different rules than `format!` — inline captures are a nightly-only feature in `format_args!`
- Event kind enum variants are not discoverable without reading source — `AuthzDeny` not `AccessDenied`
- PII classifier priority order (email → IMEI → phone → IP → custom) means test inputs must be carefully crafted to match expected category

## What was harder than expected
- Getting proptest format strings right — the macro expansion rules differ from standard `format!`
- Identifying the correct enum variants and API shapes across 6 different crates
- Understanding feature gate requirements for platform-specific modules

## Naming conventions established
- Property test files: `prop_<subject>.rs` (e.g., `prop_tls_cleartext.rs`, `prop_rasp.rs`)
- CVE regression files: `cve_maswe_<NNNN>_<description>.rs` (e.g., `cve_maswe_0050_cleartext.rs`)
- Fuzz target files: `fuzz_<target>.rs` matching runbook table names exactly

## Test patterns that worked well
- `proptest!` macro with `ProptestConfig::with_cases(1000)` for configurable case counts
- Strategy composition: `prop::string::string_regex` for domain-specific inputs, `any::<Vec<u8>>()` for fuzz-like coverage
- CVE tests as self-contained `#[test]` functions with clear MASWE reference in name and doc comments

## Missing tests that should exist now
- None — all fuzz targets, property tests, and CVE regression tests from the runbook specification are implemented

## Rules for the next milestone
- This is the final milestone in the MASVS series — no subsequent milestone to prepare for
- If extending adversarial coverage in future, follow the naming patterns established here

## Template improvements suggested
- The runbook fuzz target smoke test (`cargo fuzz list`) requires nightly Rust — consider documenting this prerequisite more prominently
- Property test case count (1000) significantly exceeds the existing pattern (256 cases) — consider standardizing across all milestones

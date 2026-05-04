# Lessons Learned — sunlit-masvs Milestone 2

## What changed
- Added `mobile_storage` module to `secure_data` behind `mobile-storage` feature flag
- Created `SensitiveBuffer` (zeroize-on-drop, explicit wipe, optional TTL), `BackupExclusion` (secure-by-default metadata marker), `MobileStoragePolicy` (classification-based policy with compliance checking)
- Added `StoragePolicyViolation` variant to `security_events::EventKind`
- 23 BDD tests + 7 E2E tests = 30 new tests total

## Design decisions and why
- Pure Rust policy objects with no platform-specific code — the actual platform keystore/backup integration happens at the FFI boundary in the consuming mobile app. This keeps the crate portable.
- Feature-gated behind `mobile-storage` — avoids adding weight for non-mobile consumers. All types only compile when the feature is enabled.
- `BackupExclusion` defaults to `Exclude` — secure-by-default pattern matching MASWE-0004 recommendation.
- `MobileStoragePolicy::for_classification()` auto-selects policy based on `DataClassification` — prevents misclassification by tying policy to the existing classification enum.
- `SensitiveBuffer` uses `Vec<u8>` with manual `Zeroize` on drop/wipe — follows existing `SecretBytes` pattern but adds TTL and explicit wipe.
- `check_compliance()` returns `Vec<SecurityEvent>` — integrates with existing event infrastructure for audit trail.

## Mistakes made
- Initially used `SecurityEvent::now()` and `event.kind()` methods that don't exist — the API uses `SecurityEvent::new(kind, severity, outcome)` constructor and public `event.kind` field.
- `DataClassification` is `#[non_exhaustive]`, so the match in `for_classification()` needed a wildcard `_` arm. Forgot this initially.

## Root causes
- Assumed `SecurityEvent` had convenience constructors based on M1 lessons file references. Should have checked the actual API before writing test assertions.
- `#[non_exhaustive]` enums from external crates require wildcard arms — a common Rust pattern that's easy to overlook when matching all known variants.

## What was harder than expected
- Nothing was particularly difficult — the existing crate patterns (secret wrappers, zeroize, security events) were well-established and easy to follow.

## Naming conventions established
- Module: `mobile_storage` (underscore-separated, matches existing module pattern)
- Feature flag: `mobile-storage` (kebab-case, matches Cargo convention)
- Types: `SensitiveBuffer`, `BackupExclusion`, `MobileStoragePolicy` (PascalCase, descriptive)
- EventKind variant: `StoragePolicyViolation` (PascalCase, follows existing variants like `TlsViolation`)
- Test files: `mobile_storage_tests.rs` (BDD), `e2e_sunlit_masvs_m2.rs` (E2E)

## Test patterns that worked well
- BDD-style `given_*_when_*_then_*` test names matching runbook scenario tables
- Separating BDD (23 tests) and E2E (7 tests) into distinct files
- Testing `check_compliance()` with various encryption/hardware combinations
- Round-trip JSON serialization tests for `BackupExclusion`
- TTL expiry test with zero-duration TTL + short sleep for deterministic behavior

## Missing tests that should exist now
- Fuzz target for `SensitiveBuffer` with arbitrary byte inputs (deferred to M9 per runbook)
- Property tests for `MobileStoragePolicy` with arbitrary `DataClassification` values (deferred to M9)

## Rules for the next milestone
- Always check `SecurityEvent` constructor signature before writing test assertions — use `SecurityEvent::new(kind, severity, outcome)` not hypothetical convenience methods
- Always add wildcard `_` arm when matching `#[non_exhaustive]` enums from other crates
- Verify feature gating by running both `cargo test --workspace` (feature off) and `cargo test -p <crate> --features <feature>` (feature on)

## Template improvements suggested
- None — the M2 runbook was clear and well-structured.

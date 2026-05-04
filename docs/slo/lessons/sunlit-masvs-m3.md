# Lessons Learned — sunlit-masvs Milestone 3

## What changed
- Added `biometric`, `device_binding`, and `step_up` modules to `secure_identity` behind `biometric` feature flag
- Created `BiometricPolicy` (validates biometric auth results against configurable class/binding/enrollment policy), `DeviceCredentialClaim` (device binding types), `StepUpPolicy` (time-based step-up auth for sensitive operations)
- Added `BiometricAuthFailure` and `StepUpAuthFailure` variants to `security_events::EventKind`
- 8 BDD biometric tests + 8 BDD step-up tests = 16 new tests total

## Design decisions and why
- Pure Rust policy objects — validates platform biometric results (attestations/proofs), never touches raw biometric data. Platform integration happens at the FFI boundary in the consuming mobile app.
- Feature-gated behind `biometric` — follows `mobile-storage` pattern from M2. Avoids adding weight for non-mobile consumers.
- `BiometricClass` uses `PartialOrd`/`Ord` derive with variant ordering (Class1 < Class2 < Class3) — enables simple `result.biometric_class < policy.minimum_class` comparison.
- `StepUpPolicy::always()` uses `max_auth_age: None` to model "always required" — cleaner than `Duration::ZERO` which would still allow exact-zero age.
- `validate_with_events()` / `evaluate_with_events()` pattern returns `Vec<SecurityEvent>` — follows M2's `check_compliance()` pattern for security event integration.
- Enrollment change detection via optional `current_enrollment_id` parameter — caller provides current state, policy validates against binding.

## Mistakes made
- None significant — applied M2 lessons about `SecurityEvent::new()` constructor and `#[non_exhaustive]` patterns from the start.

## Root causes
- N/A

## What was harder than expected
- Nothing — the existing crate patterns (feature gating, event emission, policy objects) were well-established from M1 and M2.

## Naming conventions established
- Modules: `biometric`, `device_binding`, `step_up` (underscore-separated, matches existing module pattern)
- Feature flag: `biometric` (single word, matches Cargo convention)
- Types: `BiometricPolicy`, `BiometricAuthResult`, `BiometricValidation`, `BiometricClass`, `CryptoBinding`, `BiometricRejection`, `DeviceCredentialClaim`, `DeviceBindingType`, `StepUpPolicy`, `StepUpDecision` (PascalCase, descriptive)
- EventKind variants: `BiometricAuthFailure`, `StepUpAuthFailure` (PascalCase, follows `AuthnFailure` pattern)
- Test files: `biometric_tests.rs` (BDD biometric), `step_up_tests.rs` (BDD step-up)

## Test patterns that worked well
- BDD-style `given_*_when_*_then_*` test names matching runbook scenario tables
- Separating biometric and step-up tests into distinct files
- Testing both `validate()` (returns decision) and `validate_with_events()` (returns security events)
- Edge case testing: exact threshold boundary, matching enrollment IDs, device credential allow/disallow

## Missing tests that should exist now
- Fuzz target for `BiometricAuthResult` validation (deferred to M9 per runbook)
- Property tests for `StepUpPolicy` with arbitrary durations (deferred to M9)

## Rules for the next milestone
- Continue using `SecurityEvent::new(kind, severity, outcome)` constructor — verified pattern
- Feature-gate new mobile modules consistently (cfg attribute on module in lib.rs + cfg attribute in test file)
- `validate_with_events()` pattern works well for policy objects that emit security events — reuse in M4
- Always add wildcard `_` arm when matching `#[non_exhaustive]` enums from other crates

## Template improvements suggested
- None — the M3 runbook was clear and well-structured.

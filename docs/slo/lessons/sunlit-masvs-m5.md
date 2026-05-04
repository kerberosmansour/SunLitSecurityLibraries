# Lessons Learned — sunlit-masvs Milestone 5

## What changed
- Created new `secure_resilience` crate with environment detection signal types, app integrity verification, and RASP policy engine
- Added `EnvironmentThreat` and `IntegrityViolation` variants to `security_events::EventKind`
- Added `secure_resilience` to workspace members in root `Cargo.toml`
- 22 tests across 4 test files (environment, rasp, integrity BDD + E2E)

## Design decisions and why
- **AtomicU32 for threat score**: Thread-safe accumulation without requiring `&mut self` on `RaspEngine::process_signal()`. Enables shared engine across async handlers.
- **Weighted scoring with confidence multiplier**: `base_weight * confidence_percentage / 100` gives proportional threat escalation. Debugger (100 base) > Root (70) > Emulator (40) > Unknown (0).
- **ThreatLevel from score thresholds**: 0=None, 1-30=Low, 31-60=Medium, 61-99=High, 100+=Critical. A single high-confidence debugger signal immediately reaches Critical.
- **Separate IntegrityCheck modes**: Signature, store, and resource integrity are independent verification strategies with dedicated constructors (`new_signature`, `new_store_verification`, `new_resource_integrity`).
- **EventValue::Classified for labels**: Labels map uses `EventValue` not `String`. Used `DataClassification::Internal` for evidence and confidence labels.
- **No `#[non_exhaustive]` wildcard arms needed**: `EnvironmentSignal` is `#[non_exhaustive]` but defined in this crate, so match arms are exhaustive. Wildcard would cause unreachable pattern warnings.

## Mistakes made
- Initially added wildcard `_` arms in match statements for `EnvironmentSignal` — caused unreachable pattern warnings since the enum is defined in the same crate.
- Initially tried to use `serde_json::to_string()` for labels and plain `String` values — `labels` field is `BTreeMap<String, EventValue>`.

## Root causes
- Assumed labels were `BTreeMap<String, String>` without checking the actual type first.
- Applied M4 lesson about wildcard arms too broadly — it applies when matching enums from *other* crates, not your own.

## What was harder than expected
- Nothing significant — M4 lessons and existing patterns provided clear guidance.

## Naming conventions established
- Crate: `secure_resilience` (follows `secure_*` pattern)
- Modules: `environment`, `integrity`, `rasp`, `error`
- Types: `EnvironmentSignal`, `Confidence`, `ThreatLevel`, `RaspEngine`, `RaspPolicy`, `RaspDecision`, `ResponseAction`, `IntegrityCheck`, `IntegrityResult`, `IntegrityCheckResult`, `ResilienceError`
- EventKind variants: `EnvironmentThreat`, `IntegrityViolation`
- Test files: `environment_tests.rs`, `rasp_tests.rs`, `integrity_tests.rs`, `e2e_sunlit_masvs_m5.rs`

## Test patterns that worked well
- BDD-style `given_*_when_*_then_*` test names
- Separate test files per feature area (environment, rasp, integrity)
- E2E tests exercising full pipeline: signal → engine → decision + events
- Testing threat level progression through multiple signal accumulations

## Missing tests that should exist now
- Fuzz target `fuzz_environment_signal` for arbitrary signal construction (deferred to M9)
- Property tests for threat score monotonicity (deferred to M9)
- Concurrent signal processing tests with multiple threads

## Rules for the next milestone
- Use `EventValue::Classified` (not raw strings) when inserting into `SecurityEvent.labels`
- Only add wildcard `_` arms when matching `#[non_exhaustive]` enums from *other* crates
- `SecurityEvent::new(kind, severity, outcome)` remains the correct constructor
- New crates follow pattern: `Cargo.toml` → `lib.rs` with module declarations → module files → tests/
- `secure_resilience` is a pure policy engine — no I/O, no platform calls

## Observations on Milestone 6
- `secure_privacy` is another new crate — similar setup pattern to M5
- Will need regex patterns for PII classification — check if `regex` is in workspace dependencies
- Pseudonymization will use HMAC — `sha2` and `hmac` available from `security_events` dependencies
- Consent policy is a state machine — keep it simple with enum states

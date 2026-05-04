# Lessons Learned — sunlit-masvs Milestone 6

## What changed
- Created new `secure_privacy` crate with PII classification, data pseudonymization, consent tracking, and data retention policy
- Added `ConsentViolation` and `RetentionExpiry` variants to `security_events::EventKind`
- Added `secure_privacy` to workspace members in root `Cargo.toml`
- 26 tests across 5 test files (classifier, pseudonymizer, consent, retention BDD + E2E)

## Design decisions and why
- **Regex-based PII classifier**: Uses compiled regex patterns for email, phone (with `+` prefix), IPv4, and IMEI detection. Custom patterns can be added at runtime. Order matters: email → IMEI → phone → IP → custom.
- **HMAC-SHA256 for pseudonymization**: Deterministic, non-reversible, keyed with caller-provided salt. Same approach as `security_events` redaction engine's hash strategy. Produces 64-char hex output.
- **Consent as state machine**: `ConsentPolicy` tracks state (`NotCollected` → `Granted`/`Denied` → `Withdrawn`) for a single purpose. No persistence — the app provides storage. Deny-by-default: `NotCollected` blocks processing.
- **Purpose-scoped consent**: `check_consent` validates that the requested purpose matches the consented purpose. Mismatches emit `ConsentViolation` events.
- **Retention as signal, not deletion**: `RetentionPolicy` signals `Expired` status but does not delete data. Expiry emits `RetentionExpiry` security events.
- **EventValue::Classified for labels**: Following M5 pattern — all labels use `EventValue::Classified` with `DataClassification::Internal`.

## Mistakes made
- Phone regex `\+?\d[\d\s\-]{6,}\d` was too greedy — matched UUIDs (digit sequences with hyphens), IMEI numbers (15 digits), and credit card numbers (digits with hyphens).
- IMEI check was ordered after phone check, so 15-digit numbers matched phone first.

## Root causes
- Phone regex made `+` optional, allowing any digit-heavy string to match.
- Classification order didn't account for IMEI being a subset of phone pattern.

## What was harder than expected
- Getting regex specificity right for phone numbers without being too restrictive. Requiring `+` prefix is a reasonable trade-off for mobile contexts.

## Naming conventions established
- Crate: `secure_privacy` (follows `secure_*` pattern)
- Modules: `classifier`, `pseudonymizer`, `consent`, `retention`, `error`
- Types: `PiiClassifier`, `PiiClassification`, `Pseudonymizer`, `PseudonymizedValue`, `ConsentPolicy`, `ConsentPurpose`, `ConsentState`, `ConsentDecision`, `RetentionPolicy`, `RetentionStatus`, `PrivacyError`
- EventKind variants: `ConsentViolation`, `RetentionExpiry`
- Test files: `classifier_tests.rs`, `pseudonymizer_tests.rs`, `consent_tests.rs`, `retention_tests.rs`, `e2e_sunlit_masvs_m6.rs`

## Test patterns that worked well
- BDD-style `given_*_when_*_then_*` test names
- Separate test files per feature area (classifier, pseudonymizer, consent, retention)
- E2E tests exercising full pipeline: classify → pseudonymize → consent check → retention check + events
- Testing adversarial scenarios (purpose mismatch, consent denial, expired retention)

## Missing tests that should exist now
- Fuzz target `fuzz_pii_classifier` for arbitrary string classification (deferred to M9)
- Property tests for pseudonymization determinism and collision resistance (deferred to M9)
- Unicode/internationalized email and phone number patterns

## Rules for the next milestone
- Use `EventValue::Classified` (not raw strings) when inserting into `SecurityEvent.labels`
- Only add wildcard `_` arms when matching `#[non_exhaustive]` enums from *other* crates
- `SecurityEvent::new(kind, severity, outcome)` remains the correct constructor
- New crates follow pattern: `Cargo.toml` → `lib.rs` with module declarations → module files → tests/
- `secure_privacy` is a pure policy engine — no I/O, no storage, no UI

## Observations on Milestone 7
- M7 extends `security_events` with mobile-specific log sanitization — different pattern (extending existing crate, not creating new one)
- Will need to understand current `RedactionEngine` and `RedactionPolicy` before adding mobile patterns
- Device ID scrubbing may reuse patterns from `PiiClassifier` or be independent

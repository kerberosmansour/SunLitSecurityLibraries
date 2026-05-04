# Lessons Learned — sunlit-owasp Milestone 22

## What changed
- Added per-event HMAC signing and verification via `security_events::hmac::HmacEventSigner`
- Extended `SecurityEvent` with optional `parent_event_id` and `hmac` fields for correlation and tamper evidence
- Added `InMemorySink`, `FileSink`, `BatchingSink`, and the feature-gated `HttpWebhookSink`
- Added BDD and E2E coverage for HMAC tamper detection, file output, batching, and correlation
- Updated architecture and developer docs to cover the new audit-hardening flow

## Design decisions and why
- **Per-event HMAC instead of chain-linked HMAC** — simpler to operate with multiple emitters, rotation, and out-of-order delivery while still detecting post-write tampering
- **Background batching via `BatchingSink`** — keeps the hot path lightweight without forcing a Tokio runtime on all consumers
- **Feature-gated webhook sink** — `reqwest` is powerful but heavy, so the default build keeps it disabled
- **Default trait method for `try_write_event()`** — preserved the existing sealed `SecuritySink` API while adding error-aware sink paths

## Mistakes made
- Initial attempt to depend on `secure_data::SecretString` directly from `security_events` caused a Cargo dependency cycle
- Temporary-file cleanup in the rotation test initially removed only the active file and missed rotated siblings

## Root causes
- `secure_data -> secure_errors -> security_events` already existed, so adding `security_events -> secure_data` created a cycle
- The first rotation test wrote into a shared temp path rather than cleaning up a dedicated temp directory

## What was harder than expected
- Keeping the event schema additive while still exposing `parent_event_id` and `hmac` directly on `SecurityEvent`
- Preserving compatibility for existing sinks and struct-literal call sites in other crates

## Naming conventions established
- Modules: `hmac.rs`, `correlation.rs`
- Public types: `HmacEventSigner`, `HmacError`, `FileSink`, `BatchingSink`, `InMemorySink`, `HttpWebhookSink`
- Test files: `sunlit_owasp_hmac.rs`, `sunlit_owasp_sinks.rs`, `e2e_sunlit_owasp_m22.rs`

## Test patterns that worked well
- Using real temp directories under `std::env::temp_dir()` with recursive cleanup after each test
- End-to-end tamper detection by signing a real event and then mutating a field before verification
- Verifying both the default build and the optional `http-sink` feature path

## Missing tests that should exist now
- An HTTP webhook integration test behind `http-sink` using a local mock endpoint
- A stress test that verifies batched flushing behavior under sustained concurrent writes

## Rules for the next milestone
- Preserve trait compatibility with additive default methods rather than signature changes whenever possible
- Check for dependency cycles early when a milestone suggests cross-crate integration with security primitives
- Keep temp-file tests isolated in their own unique directories to guarantee cleanup

## Template improvements suggested
- Add an explicit pre-flight step to search for public struct literals before extending shared event or DTO schemas

# Lessons Learned — Milestone 9: Adversarial Testing & Fuzzing

**Date**: 2026-04-06
**Milestone**: 9 — Adversarial Testing & Fuzzing
**Status**: done

---

## What We Built

| Component | Details |
|---|---|
| `security_events::AuditChain` | SHA-256 hash-linked tamper-evident audit chain (deferred from M3). Each entry = `SHA256(prev_hash_hex \|\| event_json)`. `verify()` recomputes all hashes. |
| `prop_validation.rs` (secure_boundary) | NFC idempotency, normalize no-panic, trim never grows |
| `prop_encoding.rs` (secure_output) | No raw `<>"'` in HTML output, no `<script>` tag, no panic |
| `prop_session.rs` (secure_identity) | Session IDs always unique, creation succeeds |
| `prop_encryption.rs` (secure_data) | Roundtrip correctness; tampered ciphertext always rejected |
| `prop_redaction.rs` (security_events) | Secret never leaks verbatim; no raw newlines after sanitization |
| `prop_deny_default.rs` (secure_authz) | Empty policy always `Decision::Deny` for any subject/action/resource |
| `timing_token_compare.rs` (secure_identity) | Welch's t-test on JWT validation timing |
| `timing_crypto.rs` (secure_data) | Welch's t-test on AEAD tag verification timing |
| `cve_regression.rs` (security_events) | Log injection (CWE-117), null bytes, chain tamper detection |
| `cve_regression.rs` (secure_identity) | CVE-2015-9235 `alg:none` bypass, tampered sig, expired/wrong-issuer JWT |
| `cve_regression.rs` (secure_boundary) | Unicode normalization bypass, CRLF, homograph, email normalization |
| Fuzz targets (5 crates) | `cargo fuzz` project structures for secure_boundary, secure_output, secure_identity, secure_data, security_events |

---

## Key Design Decisions

### 1. AuditChain Hash Formula

`hash = SHA256(previous_hash_hex_bytes || event_json_bytes)`

Genesis entry uses empty-string prefix (not a special sentinel). This means:
- `verify()` is a simple loop — no special-case for the first entry
- The hash includes the *entire* event JSON, so any field mutation is detectable
- `serde_json::to_string` is used for deterministic serialization (fields are serialized in declaration order thanks to `Serialize` derive)

**Caveat**: `OffsetDateTime` serialization format may vary across `time` crate versions. If the hash format must be stable across library upgrades, consider freezing the timestamp as ISO-8601.

### 2. Timing Tests Are `#[ignore]`-ed for CI

The runbook allows this with justification. On a shared macOS machine or noisy CI runner, timing tests produce false positives. The actual constant-time property is enforced by `ring` (HMAC-SHA256) and `aes-gcm` (AES-256-GCM). Our tests use Welch's t-test with 500 samples but are marked `#[ignore]` to avoid flakiness.

Instruction for M10: Consider using dedicated CI runners or a `timing` feature flag for CI.

### 3. Fuzz Targets Are Separate Workspaces

Each fuzz crate uses `[workspace]` in its `Cargo.toml` to exclude itself from the main workspace. This is required by `cargo fuzz`. The main `cargo test --workspace` does **not** build fuzz targets.

To list fuzz targets: `cd crates/X && cargo fuzz list` (requires `cargo-fuzz` installed).

Since `cargo-fuzz` was not installed in this environment and only stable Rust was available, the fuzz targets were created as compilable structures but were not executed. They should be run in a nightly environment before production release.

### 4. `proptest` Cases Per Test

Default is 256 cases. For async tests using `tokio::runtime::Runtime::new()`, we reduce to 32–64 cases to avoid excessive overhead per test run. The async tests block on futures, so each case spins up a new tokio runtime.

### 5. CVE-2015-9235 (`alg:none`) Defense

`jsonwebtoken` v9.x (used by `secure_identity`) rejects `alg:none` by default when `Validation::new(Algorithm::HS256)` is used — only the specified algorithm is accepted. The CVE regression test confirms this is still the case and documents the expected behavior.

### 6. Clippy: `for-kv-map` Lint

When iterating over `BTreeMap`, use `.values()` instead of `(_, v) in &map` to satisfy `clippy::for_kv_map` (treated as an error with `-D warnings`).

---

## What Was Deferred from M3 (Now Completed)

The `AuditChain` with SHA-256 hash linking was marked as a stretch goal in M3. It is now fully implemented in `security_events::audit_chain`. The CVE regression tests in `security_events/tests/cve_regression.rs` include a tamper-detection test that exercises `verify()`.

---

## Gotchas

1. **`SecurityEvent` is not `Deserialize`** — only `Serialize`. This is correct for our purposes (we only need to hash serialized events), but prevents direct JSON-round-trip testing of events.

2. **`StaticDevKeyProvider` key is deterministic** — the same alias always returns the same key. This is intentional for tests but means different `StaticDevKeyProvider` instances produce compatible envelopes.

3. **`proptest` async tests** — `proptest!` macros execute synchronously. For async operations, `tokio::runtime::Runtime::new().unwrap().block_on(...)` is used inside the `proptest!` body. This is correct but slower than pure sync tests.

4. **Fuzz corpus directories** — These are in `.gitignore` (`crates/*/fuzz/corpus/`, `crates/*/fuzz/artifacts/`, `crates/*/fuzz/target/`). Initial corpus seeding was not done in this milestone — fuzz targets start from empty corpus.

---

## What Milestone 10 Needs From This One

- All crates have clean `cargo clippy -- -D warnings` — supply-chain CI gate should not encounter new warnings
- Fuzz targets are structured as separate workspaces — CI can run them on nightly runners independently
- Property tests run in < 5 seconds total — no CI time impact from M9
- `AuditChain` is published as part of `security_events` public API — M10 CI gate can include audit chain tests

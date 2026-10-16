# Changelog

All notable user-facing changes should be recorded here once the crates are
published.

This project follows the spirit of [Keep a Changelog](https://keepachangelog.com/)
and uses Cargo-compatible semantic versioning. Pre-1.0 releases may still make
breaking API changes, but security fixes and migration notes should be explicit.

## Unreleased

### Security

- Add a dedicated `InlineScriptStringEncoder` that preserves JavaScript lexical
  escaping while neutralizing the HTML script raw-text boundary. Clarify that
  `JsStringEncoder` is for non-HTML JavaScript and that `JsonEncoder` transforms
  an already serialized JSON document; remove the raw-expression guide example.
- Harden URI output validation against browser control normalization and HTML
  attribute breakout; copyable examples now compose URI validation with HTML
  attribute encoding.
- Enforce Axum JSON/XML request limits while streaming the body and honor
  request-specific XML limits, preventing full over-limit allocation.
- Parse and retain `SafeUrl` values with the locked WHATWG URL implementation,
  rejecting credentials, fragments, backslashes and alternate numeric protected
  hosts; add a resolved-address policy helper for DNS pinning integrations.
- Extend `SafeUrl` literal and resolver checks to fail closed for carrier-grade,
  provider-metadata, documentation, benchmarking, reserved and non-global IPv6
  destinations. Canonicalize same-origin `SafeRedirectUrl` paths and reject raw
  or encoded separator/control parser differentials.

### Dependency assurance

- Keep Semgrep's resolver-consistent MCP 1.29.0 graph while enforcing a bounded
  2026-10-29 exception for GHSA-84m7-p3x7-pcfv. The OSV report retains the
  advisory; CI rejects identity drift, expiry, stale records and every malware
  identity. This repository invokes `semgrep scan` and does not expose the
  affected stateful HTTP MCP server. Upgrade when upstream Semgrep admits MCP
  1.30.0 or later.
- Update the resolved `smallvec` patch from 1.15.1 to 1.15.2 in the workspace
  and isolated HMAC consumer locks. The reviewed delta fixes zero-inline
  `DrainFilter::keep_rest` ownership handling and changes internal empty-storage
  construction without changing this workspace's enabled features or adding a
  dependency. The optional `debugger_visualizer` feature remains unsupported by
  the upstream package because its referenced Natvis file is absent; this
  workspace does not enable that feature.

## [0.4.0] — 2026-10-15

### Identity and migration

- Add an explicit reduced HMAC-only profile with an isolated normal/build consumer
  graph that excludes the rsa Rust package; preserve legacy default/asymmetric/SSH
  APIs through named feature groups. Cargo feature unification can restore RSA.
- Reuse admitted ring HMAC and vendor JWT validation, checked process-provider
  initialization and fixed conflict errors. Bound new-profile tokens/keys and
  preserve signature, issuer/audience and expiry checks; add real consumer/startup
  scenarios and Kani acceptance-kernel obligations. No external identity/version/
  checksum change. The capability begins in 0.4.0 and is absent from immutable 0.3.0.
- Default asymmetric/SSH behavior is preserved. Previous no-default-feature
  asymmetric callers explicitly select `asymmetric-jwt` and/or `ssh-public-keys`;
  reduced consumers select `jwt-hmac` and initialize the checked provider before
  direct vendor JWT use. See [migration](docs/dev-guide/jwt-hmac-profile.md).
- Coordinate all twelve crates at 0.4.0; the other eleven library APIs and all
  external versions/sources/checksums, audits and exact advisory exceptions stay
  unchanged. Mobile physical-device/consumer integration limits remain.


## [0.3.0] — 2026-10-14

### Mobile storage and migration

- Add the sealed `MobileKeyProvider<B>` and typed native errors behind the existing `mobile-storage` feature. Reuse envelope AEAD; keep long-lived KEKs native and bound alias/version, frame size and operation custody. Decrypt never recreates keys.
- Include SDK-only iOS Keychain and AndroidKeyStore wrapping reference sources. Real simulator/emulator restart, tamper and key-deletion qualification passes. Physical-device custody, backup/passcode changes, hard preemption and application reconciliation remain unqualified.
- Require iOS `WhenPasscodeSetThisDeviceOnly`, no fallback, with explicit trusted re-enrolment after passcode removal/reset. Hardware-required policy rejects software references.
- Add typed `DataError::MobileKeyProvider { kind }` under `mobile-storage`; the error enum remains non-exhaustive. Qualify a native binding using the [migration guide](docs/dev-guide/mobile-bridge-migration.md). No existing envelope format change.
- Coordinate all twelve crate versions as 0.3.0; other crate APIs are unchanged. Preserve every external locked version/source/checksum, cargo-vet audit and exact expiring advisory exception.


## [0.2.1] — 2026-10-14

### Security and dependency admission

- Fix issue #55: `secure_authz::DefaultAuthorizer` binds cached decisions to the
  exact ordered roles, so role removal and grants cannot reuse stale decisions.
  Preserve public cache APIs, TTL and capacity; isolate manually seeded entries
  from internal authorizer entries. Identity-provider freshness remains required.
- Repair four rustls advisories published 2026-10-14 by upgrading only rustls
  0.23.45 → 0.23.46 and recording a reviewed cargo-vet delta. Preserve the rest of
  the locked graph and existing exact, expiring exception boundaries.
- Require checksum-pinned OSV scans of resolved direct/transitive dependencies
  before CI builds and in the daily SCA workflow. Reject partial/empty scans,
  scanner/network failures and malicious-package waivers. Preserve JSON evidence
  without executing dependency install/build scripts; document Codex/Claude rules.
- Scan and freeze Cargo audit-tool/Kani graphs before source builds. Keep cargo-vet
  evaluation code unchanged while replacing its obsolete transport/progress
  dependency requirements with a documented manifest-only overlay. Park the
  optional cargo-geiger inventory because the latest tool still has unpatched
  dependencies; retain required source/native/SAST/formal checks.

- Freeze the admitted Semgrep 1.180.0 wheel graph and remove the redundant
  example-service DAST job by explicit maintainer decision. OSV admission replaces
  its required check, with all twenty other required checks retained.
- Coordinate all twelve libraries at 0.2.1. Scan exact packaged locks before verification
  and publication; bind packaged source/manifest authority and dependency
  checksums to the clean reviewed release and already verified siblings.

## [0.2.0] — 2026-10-14

### Security and migration

- Coordinate all twelve library crates at 0.2.0; update sibling dependency requirements and installation examples. The two service crates remain unpublished fixtures.
- JWKS production fetches require HTTPS without userinfo/fragments, disable redirects, and enforce a 10-second timeout and 1 MiB response limit. Development HTTP is explicit and restricted to numeric loopback. Migrate local fixtures to the development constructor.
- Hybrid encapsulation Debug redacts derived keys. Prompt validation rejects additional bidirectional controls. Circuit-breaker generations prevent stale completions from changing current state; unwind releases the matching half-open probe reservation.
- Disable unused Actix HTTP/2 features that retained an unpatched h2 dependency. Consumers enabling those features separately must audit their own graph.
- The fips feature does not replace envelope encryption with a validated backend. Remove the misleading envelope FIPS field and correct documentation; the dependency feature label is not a validation certificate. Generic event sinks require explicit RedactionEngine processing; classification alone does not redact arbitrary fields.
- Tighten source-attestation checks and improve bounded proof harnesses. TLC models are abstract state models, and bounded Kani evidence does not establish cryptographic correctness or RNG uniqueness.

### Dependencies and verification

- Apply targeted advisory repairs and paired HKDF/SHA updates while preserving other audited versions. Hold lru at exactly 0.18.3 and xxhash-rust at exactly 0.8.15 pending further upstream review; newer versions are not automatically accepted.
- Add honest AI-assisted cargo-vet records and force source-built AWS-LC; reject system-library overrides, unreviewed native features and untrusted formatter binaries. Two exact native-crypto audit exceptions, the unchanged smartstring maintenance advisory and the unreachable xxhash custom-secret advisory expire 2026-11-14. Redis uses default-secret hashing only. The existing RSA timing exception is revalidated and expires on the same date; it applies to public-key signature verification, not private-key operations.
- Simplify CI duplication, make daily SCA/manual fixture drills read-only, retain OS/feature coverage, and checksum the formal-tool download. Native dependency guards fail on exception expiry.

## Previously published additions

### Added

- `secure_identity 0.1.10` adds a bounded, fail-closed OpenSSH public-key
  validator for `ssh-ed25519`, `ssh-rsa`, and ECDSA NIST P-256/P-384/P-521.
  A fixed-capacity decoder and borrowed-slice field parser pin raw outer and
  embedded algorithms, reject trailing wire data without length-directed
  allocations, validate public-key parameters and curve membership with
  audited RustCrypto primitives, and return no decoded key or comment material.
  RSA parser compatibility defaults to OpenSSH's 1,024–16,384-bit range; the
  companion minimum-bits API enforces stronger deployment policy in-call.
- `security_events 0.1.3` adds `HardDenyTargetsLayer`, a vendor-agnostic global
  `tracing-subscriber` boundary for dependency targets that may carry prompts, tool arguments,
  results, provider bodies, paths, or identities. Exact roots and their `::` descendants are denied
  from both callsite registration and runtime enablement, so verbose `EnvFilter` directives cannot
  re-enable them. Near-prefix and unlisted targets remain visible by design.

## secure_identity 0.1.9 - 2026-08-01

### Changed

- `jsonwebtoken` 10.3 -> 11.0. The feature selection is **unchanged**:
  `features = ["rust_crypto"]` is kept, because those features still exist in
  v11 and dropping them would remove the crypto provider — ed25519-dalek, hmac,
  p256, p384, rsa and sha2 — from a security crate. Nothing errors on a
  *missing* feature, so that mistake would have compiled cleanly and lost
  algorithm support at runtime.

  An earlier reading of the crates.io API suggested v11 had removed all cargo
  features. That reading came from parsing an API *error* response with
  `.get('version',{}).get('features',{})`, which renders a failed request as an
  empty map. Verified three ways before this bump, the decisive one being a real
  resolve: `jsonwebtoken 11` with `features = ["use_pem","rust_crypto"]` is
  accepted by `cargo metadata` (exit 0), while a fabricated feature name is
  rejected (exit 101) — the second is the control that makes the first mean
  something.

- No source changes were required. v11's breaking list does not touch anything
  this crate uses: it has no `insecure_disable_signature_validation`, no
  `Jwk::thumbprint`, no `try_get_hmac_secret`, no `JwkUtils`, and no exhaustive
  `match` over `Algorithm` — which matters, because a wildcard arm added to
  silence `#[non_exhaustive]` is how an unexpected algorithm gets silently
  accepted.

### Why this release exists

`secure_identity 0.1.8` pinned `jsonwebtoken 10.3.0`, which constrained the
whole dependency graph of every consumer. A downstream bump to v11 resolved
both majors together and failed with `expected DecodingKey, found
jsonwebtoken::decoding::DecodingKey` — two distinct types with one name. That
could not be fixed downstream; it needed this release.

## secure_authz 0.1.3 - 2026-05-21

- Reliability/deployment fix: `secure_authz` no longer reads the Casbin RBAC
  model from the filesystem at runtime. `DefaultPolicyEngine::new_empty()`
  previously loaded the model via
  `casbin::DefaultModel::from_file(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/rbac_model.conf"))`
  and an empty-CSV `FileAdapter`. `env!("CARGO_MANIFEST_DIR")` bakes the **build
  machine's** absolute path into the binary, so any deployment that does not
  ship the crate source tree (e.g. a distroless container image) crashed at
  startup with `policy load failed: Casbin Io Error: NotFound`. The model is now
  embedded with `include_str!` and policies start from an in-memory adapter, so
  the compiled binary needs **no filesystem access** to initialize the policy
  engine. No public API or authorization-behavior change for callers.

## [0.1.3] - 2026-05-07

- Security: fixed `secure_boundary::safe_types::SafeUrl` userinfo handling so SSRF
  checks apply to the effective hostname after `@`, blocking private,
  loopback, and link-local IP targets smuggled through URL userinfo syntax.

## [0.1.2] - 2026-05-06

- Published the per-rule ANSSI Rust Secure Coding Guidelines mapping. All 61
  pinned rules now carry a posture (`compliant`, `partial`, `waived`, or
  `N/A`) with concrete evidence pointers or named compensating controls, so EU
  consumers can cite the mapping in procurement reviews and IEC 62443-4-1 SD-3
  audit support.
- New CI lint at `scripts/anssi-mapping-lint.sh` gates the ANSSI Rust
  compliance mapping at `docs/compliance/anssi-rust.md`. Validates that
  the ANSSI commit pin matches, the rule count is exactly 61, every
  Status column is populated, and every `compliant` row's Evidence
  pointer resolves to a real artifact (file:line, clippy lint, docs
  path, or test name). The lint is no-op while rows remain `unfilled`
  (M1 placeholder) and becomes gating once M2 populates evidence. Wired
  into the supply-chain CI job. Closes #20.
- You can now opt into hybrid X25519 + ML-KEM-768 envelope key wrap in
  `secure_data` with `--features pq`. New writes that select
  `CryptoAlgorithm::HybridX25519MlKem768` produce v2 envelopes whose data key
  is wrapped as `ML-KEM-768 ciphertext || X25519 share || AES-GCM-wrapped DEK`
  with `combiner_id = 0x01`; existing classical v1 envelopes continue to
  decrypt unchanged. The `pq` path is labelled `pending_cmvp` and makes no
  FIPS-validation claim. Closes #8.
- `secure_data::pq::fips_status() -> Option<&'static str>` reports the
  runtime FIPS posture of the PQ path. `None` when `pq` is not enabled;
  `Some("pending_cmvp")` when `pq` is enabled (no CMVP cert covers
  ML-KEM-768 as of 2026-05, so the honest label is validation-pending).
  A future `pq-aws-lc` feature will return `Some("validated")` after a
  CMVP cert lands. CI lint at `scripts/lint-fips-pq-claims.sh` blocks any
  regression of the documentation posture by failing the build on
  forbidden phrasings. Closes #10.
- `secure_data` adds `AlgorithmPolicy::with_min_envelope_version(u8)` and
  `secure_data::envelope::decrypt_with_policy` for downgrade-attack
  defence on the decrypt side. A consumer that requires v2-or-higher
  envelopes can now reject v1 envelopes at the structural boundary
  before any AEAD work; v1 envelopes return
  `DataError::AlgorithmRejectedByPolicy { reason }`. Default
  `AlgorithmPolicy` continues to accept every envelope. Closes #9.
- `secure_data` reserves a post-quantum migration path. The crate now exposes a
  `CryptoAlgorithm::HybridX25519MlKem768` enum slot, an optional
  `EncryptionEnvelope::combiner_id: Option<u8>` wire-format field, and a public `pq` module with
  size constants and combiner identifiers. The migration plan
  (`docs/slo/design/pq-migration-plan.md`) is the authoritative source for the
  wire format, the hybrid-KEM design (X25519 ⊕ ML-KEM-768 / HKDF-SHA-256 per
  research), the FIPS-track posture (monitor only — no CMVP cert covers
  ML-KEM as of 2026-05), and the rollout playbook for downstream consumers.
  Existing classical envelopes continue to encrypt and decrypt unchanged;
  `combiner_id` is omitted from the wire for classical envelopes (serde
  `skip_serializing_if`). Pre-M1 envelopes deserialize cleanly with
  `combiner_id == None`. Hybrid encryption returns `DataError::PqUnavailable`
  on builds without `--features pq`; v2 hybrid envelopes presented to a non-`pq` build return `DataError::PqFeatureRequired`
  with no silent fallback. Closes #7.
- The Kani advisory CI lane is extended further (M3) to `secure_errors`,
  with new harnesses on `secure_data` for per-algorithm nonce length
  invariants. The `secure_errors` harnesses prove that
  `into_response_parts(&err)` produces a 4xx/5xx status, a non-empty
  static `code`, and a `code` drawn from a fixed whitelist — so no
  internal error text can leak through `PublicError`. Closes #13.
- The Kani advisory CI lane is extended (M2) to `secure_authz` and
  `secure_boundary`. New harnesses prove the deny-by-default discriminant
  invariants on `Decision`, mutual exclusivity of `Allow`/`Deny`, and the
  request-limit comparison invariants on `RequestLimits` (depth, field
  count, body size, plus a default-non-zero guard). All harnesses are
  gated by `#![cfg(kani)]` so regular builds remain unaffected. Closes #12.
- A new advisory CI lane runs `cargo kani` (pinned to `0.62.0`, 15-minute
  cap) against the workspace on every PR. M1 ships the bootstrap proof in
  `secure_data` (12-byte AES-256-GCM nonce remains non-zero through the
  envelope-builder pipeline; AEAD primitive itself axiomatised per the
  research synthesis). The harness lives in `crates/secure_data/src/proofs.rs`
  under `#![cfg(kani)]` so it has zero impact on regular builds. Promotion
  of the lane to a blocking gate is a separate runbook after at least one
  release cycle of stable signal. See `docs/dev-guide/formal-verification.md`
  for the proof catalogue and the TLA+ specs for
  `secure_resilience::circuit_breaker` and `secure_identity` session+step-up.
  Closes #11.
- `secure_resilience` now ships a TLA+-verified circuit breaker
  (`CircuitBreaker`, `CircuitBreakerPolicy`, `CircuitBreakerState`,
  `CircuitBreakerError`). Closed/open/half-open state machine with the
  load-bearing **single-probe rule**: in HalfOpen, exactly one probe
  call may be in flight at a time; concurrent callers receive
  `CircuitBreakerError::ProbeInFlight`. Configurable failure threshold
  (default 5) and open duration (default 30s). The design is verified
  by `specs/CircuitBreaker.tla` (Hardened) and shown to be
  load-bearing by `specs/CircuitBreakerNaive.tla`, which TLC must
  reject (`NoDoubleProbe` counterexample documented in
  `specs/CircuitBreaker.trace.md`). Verified-design doc at
  `docs/slo/design/circuit-breaker-verified.md`. 7 BDD scenarios
  including a live concurrent-double-probe rejection. Closes #14.
- New advisory CI lane `.github/workflows/tla.yml` runs TLC (pinned to
  TLA+ Tools v1.8.0, 10-min cap) on every PR. M5 ships the
  `secure_identity` session+step-up TLA+ spec — three safety properties
  (no privileged action without step-up, no expired-session reuse, the
  step-up window is bounded) verified at bound `MaxSessionTicks=5,
  MaxStepUpTicks=2, MaxPrivActionAttempts=3`. The Naive variant deliberately
  omits the step-up gate; TLC must find the documented counterexample (verified per
  `specs/SessionStepUp.trace.md`). Verified-design doc at
  `docs/slo/design/session-step-up-verified.md`. The same lane now also runs
  the CircuitBreaker hardened and naive specs. Closes #15.
- The supply-chain CI lane now runs `cargo-geiger` (pinned to `0.13.0`) on
  every PR and uploads the JSON artifact (30-day retention). The advisory step
  surfaces transitive `unsafe` usage in the dependency tree; deltas are
  visible to reviewers on the PR via artifact diff. Local parity is
  available via `bash scripts/audit.sh` (or `pwsh scripts/audit.ps1`).
  The current measured baseline (root = `secure_reference_service`,
  `--all-features`) is **22 636 transitive unsafe expressions used / 48 192
  available**; SunLit crates contribute zero. Threshold = baseline + 10 %
  headroom. Promotion of the threshold to a blocking gate is a separate
  future runbook. See `docs/dev-guide/unsafe-budget.md`.
- All workspace crates are now `#![forbid(unsafe_code)]` (added to
  `secure_smoke_service`; the other 13 crates already had the attribute). The
  posture is regression-tested by `crates/security_core/tests/no_unsafe_code.rs`
  — any future removal fails the build with a named-crate error. A companion
  scan also asserts no `unsafe ` keyword appears anywhere in `crates/*/src/`.
- Added public open-source governance files: license, notice, trademarks,
  contributing guide, security policy, code of conduct, issue templates, and PR
  template.
- Normalized runbooks and milestone artifacts under `docs/slo/`.


AWS KMS dependency maintenance: the JSON parser advisory is repaired at aws-smithy-json 0.62.7 with the minimum compatible runtime/type/schema batch. The retained generated AWS SDK versions are pinned to avoid adopting new schema/codec paths during this review. Those new APIs have independently identified defects and are outside this provider's call path; two exact temporary cargo-vet exceptions expire 2026-11-14. They are not a general approval of those crates. The repository lock/audits describe its tested graph; downstream consumers must audit their final resolved graph and any custom SDK/runtime use.

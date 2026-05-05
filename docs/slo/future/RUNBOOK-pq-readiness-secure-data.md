# Post-Quantum Readiness in `secure_data` — SunLitSecurityLibraries (AI-First Runbook v4)

> **Purpose**: Add a documented, executable post-quantum migration path to `secure_data` — a reserved `CryptoAlgorithm` enum slot, an explicit migration plan, and a feature-gated hybrid (X25519 + ML-KEM-768) KEM implementation for envelope key wrap — without breaking any existing AES-256-GCM or XChaCha20-Poly1305 envelope.
> **Audience**: AI coding agents first, humans second.
> **Core philosophy**: Prefer reserving an enum slot today over migrating consumers later. Prefer concrete primitives behind a feature flag over abstract policy declarations. Prefer wire-format versioning over silent schema evolution.
> **Prerequisite reading**: [README.md](../../../README.md), [ARCHITECTURE.md](../../../ARCHITECTURE.md), [THREAT_MODEL.md](../../../THREAT_MODEL.md), [`docs/slo/research/pq-readiness-secure-data/`](../research/pq-readiness-secure-data/), [`docs/slo/idea/pq-readiness-secure-data.md`](../idea/pq-readiness-secure-data.md), [v4 template](../templates/runbook-template_v_4_template.md). Sections 4 (Carmack-style development rules), 6 (Global execution rules), 7 (Pre-milestone protocol), 8 (Post-milestone protocol), 11 (BDD/runtime validation rules), 12 (Dependency/migration/refactor policy), 13–14 (Evidence Log & Self-Review Gate) of the v4 template apply to every milestone in this runbook.

---

## 1. Runbook Metadata

| Field | Value |
|---|---|
| Runbook ID | `pq-readiness-secure-data` |
| Project name | SunLitSecurityLibraries |
| Primary stack | Rust 2021, Cargo workspace, axum/Actix Web service consumers |
| Primary package/app names | `secure_data` |
| Prefix for tests and lesson files | `pqd` |
| Default unit test command | `cargo test -p secure_data` |
| Default integration/BDD test command | `cargo test -p secure_data --all-features` |
| Default E2E/runtime validation command | `cargo test -p secure_data --test 'e2e_*' --all-features` |
| Default build/boot command | `cargo build --workspace` |
| Default formatter command | `cargo fmt --all -- --check` |
| Default static analysis / lint command | `cargo clippy -p secure_data --all-targets --all-features -- -D warnings` |
| Default dependency / security audit command | `cargo audit && cargo deny check && cargo vet` |
| Default debugger or state-inspection tool | `cargo test -- --nocapture` + `lldb` for unit-level; `cargo expand` for macro-level |
| Allowed new dependencies by default | `none` — each milestone names them |
| Schema/config migration allowed by default | `no` — except M1 introduces a new `EncryptionEnvelope` version field with documented backwards-compat |
| Public interfaces stable by default | `yes` |

### Public interfaces that must remain stable unless explicitly listed otherwise

- `secure_data::envelope::{encrypt_for_storage, decrypt_for_use, encrypt_with_policy}`
- `secure_data::algorithm::{CryptoAlgorithm, AlgorithmPolicy}`
- `secure_data::kms::KeyProvider` (trait shape)
- `secure_data::secret::SecretString`
- All `secure_data` feature flags currently published: `vault`, `aws-kms`, `fips`, `password`, `azure-kv`, `mobile-storage`

---

## 2. Milestone Tracker

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | Migration plan + reserved `CryptoAlgorithm::HybridX25519MlKem768` slot + envelope `combiner_id` field | `done` | 2026-05-05 | 2026-05-05 | [`docs/slo/lessons/pqd-m1.md`](../lessons/pqd-m1.md) | [`docs/slo/completion/pqd-m1.md`](../completion/pqd-m1.md) — public surface reserved; `pq` feature flag (no deps yet); migration plan locks RustCrypto `ml-kem` v0.3.0, concat+HKDF wire format, monitor-only FIPS posture; 12 BDD scenarios green. Closes #7. |
| 2 | Hybrid X25519+ML-KEM-768 KEM behind `pq` feature; envelope encryption end-to-end | `done` | 2026-05-06 | 2026-05-06 | [`docs/slo/lessons/pqd-m2.md`](../lessons/pqd-m2.md) | [`docs/slo/completion/pqd-m2.md`](../completion/pqd-m2.md) — v2 hybrid envelopes round-trip behind `--features pq`; KAT and abuse scenarios green. Closes #8. |
| 3 | Backwards-compat decrypt + downgrade-attack regression tests + algorithm-policy enforcement | `done` | 2026-05-06 | 2026-05-06 | [`docs/slo/lessons/pqd-m3.md`](../lessons/pqd-m3.md) | [`docs/slo/completion/pqd-m3.md`](../completion/pqd-m3.md) — `AlgorithmPolicy::with_min_envelope_version`, `decrypt_with_policy`, 4-cell compat matrix + 2 abuse cases. Closes #9. |
| 4 | FIPS-track readiness note + `fips` × `pq` interaction documentation | `done` | 2026-05-06 | 2026-05-06 | [`docs/slo/lessons/pqd-m4.md`](../lessons/pqd-m4.md) | [`docs/slo/completion/pqd-m4.md`](../completion/pqd-m4.md) — `pq::fips_status() = Some("pending_cmvp")` runtime audit signal; CI lint at `scripts/lint-fips-pq-claims.sh` blocks forbidden phrasings; dev-guide `fips × pq` section. Closes #10. |

<!-- Status values: not_started | in_progress | blocked | done -->

---

## 3. End-to-End Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         secure_data envelope encryption                       │
│                                                                              │
│  Application                                                                 │
│      │                                                                       │
│      ▼                                                                       │
│  encrypt_for_storage(plaintext, key_alias, provider)                         │
│      │                                                                       │
│      ▼                                                                       │
│  AlgorithmPolicy ─── selects ──▶ CryptoAlgorithm                             │
│                                  ├─ Aes256Gcm           (existing, default)  │
│                                  ├─ XChaCha20Poly1305   (existing)           │
│                                  └─ HybridX25519MlKem768 ─── NEW (M1 slot,   │
│                                                            M2 implementation)│
│      │                                                                       │
│      ▼                                                                       │
│  KeyProvider ─── wrap_data_key ───▶  KEK    classical: AES-KW or AES-GCM     │
│                                            hybrid:    X25519 share concat   │
│                                                       ML-KEM-768 ct,        │
│                                                       fed through HKDF-256  │
│      │                                                                       │
│      ▼                                                                       │
│  EncryptionEnvelope { version: u8, algorithm, ciphertext, ... }              │
│  - version=1 for existing AEAD envelopes (legacy field semantics)            │
│  - version=2 for hybrid-PQ envelopes with combiner_id byte (NEW M1)          │
│                                                                              │
│  Legend: ─── existing   - - - new   ▶ data flow                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Existing/New/Changed | Milestone | Key Interfaces |
|---|---|---|---|---|
| `secure_data::algorithm::CryptoAlgorithm` | Enum identifying envelope cipher/KEM | changed (new variant) | M1 | `CryptoAlgorithm::HybridX25519MlKem768` |
| `secure_data::envelope::EncryptionEnvelope` | Wire-format struct for encrypted blobs | changed (new `version` field, hybrid `combiner_id` byte) | M1 | (de)serialization shape |
| `secure_data::pq` | New module: hybrid KEM construction + KEM combiner + KAT tests | new | M2 | `pq::hybrid_encapsulate`, `pq::hybrid_decapsulate` |
| `pq` feature flag | Gates ML-KEM dependency | new | M2 | `cargo build -p secure_data --features pq` |
| `secure_data::policy` (existing) | Algorithm-policy enforcement (rejection of weak alg) | changed | M3 | `AlgorithmPolicy::reject_legacy_pq_only_consumers` (semantics) |
| `docs/dev-guide/secure-data-pq.md` | Consumer-facing dev guide for PQ usage | new | M2/M3 | rendered from rustdoc + worked examples |
| `docs/slo/design/pq-migration-plan.md` | Authoritative migration plan (M1 output) | new | M1 | written for downstream consumers |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Bounded? | Failure Mode | Milestone |
|---|---|---|---|---|---|---|
| encrypt with hybrid KEM | application | provider | `KeyProvider::wrap_data_key` | yes (key sizes fixed) | returns `DataError::PqUnavailable` if `pq` feature disabled | M2 |
| decrypt v1 envelope post-PQ-rollout | application | provider | existing AEAD path | yes | unchanged | M3 |
| decrypt v2 envelope on consumer without `pq` | application | provider | hybrid KEM path | yes | returns explicit `DataError::PqFeatureRequired` (no silent fallback) | M3 |

---

## 4. Carmack-Style Development Best Practices

This runbook inherits §4 of the [v4 template](../templates/runbook-template_v_4_template.md) verbatim. Project-specific bindings:

| Requirement | Tool/Command |
|---|---|
| Interactive debugger | `cargo test -- --nocapture`; `lldb` against `cargo build --tests`; `cargo expand -p secure_data` for macro inspection |
| Formatter | `cargo fmt --all -- --check` |
| Lint | `cargo clippy -p secure_data --all-targets --all-features -- -D warnings` |
| Security/dependency audit | `cargo audit && cargo deny check && cargo vet` |
| Property tests | `cargo test -p secure_data -- prop_` |
| Fuzz harnesses | `cargo +nightly fuzz run -p secure_data <target>` |

**Resource bounds for this runbook**: ML-KEM-768 ciphertext is 1088 bytes; X25519 share is 32 bytes; HKDF-SHA-256 output is 32 bytes. These sizes are fixed by the standard and encoded as constants. No new unbounded growth introduced.

**Invariants this runbook adds**:
- v1 envelopes never embed an ML-KEM ciphertext (size mismatch caught at deserialize).
- v2 envelopes always carry a non-zero `combiner_id` byte.
- HKDF-SHA-256 output for the data-key wrap is exactly 32 bytes (assert at production boundary).
- AlgorithmPolicy rejection emits a `secure_data::error::DataError::AlgorithmRejectedByPolicy` — never a silent fallback.

---

## 5. High-Level Design for State Modeling / Formal Verification

`N/A — encryption is single-shot, stateless from the envelope's perspective. There is no concurrency or interleaving risk in the encrypt/decrypt path. Property-based tests cover the input space; KAT vectors cover the standard's known-answer cases. Formal verification (Kani / TLA+) for `secure_data` is in the [formal-verification-kani-tla runbook](RUNBOOK-formal-verification-kani-tla.md), not this one.`

---

## 6. Global Execution Rules

Inherits §6 of the [v4 template](../templates/runbook-template_v_4_template.md). Explicit reminders for this runbook:

- **6.1 Stay inside scope** — do not change any `KeyProvider` implementation (Vault, AWS-KMS, Azure-KV) in M1–M3. KMS PQ integration is post-1.0.
- **6.4 Resource bounds** — encode ML-KEM-768 fixed sizes as `const` in `secure_data::pq::sizes`; assert.
- **6.5 Static analysis** — every milestone runs the full `cargo audit && cargo deny check && cargo vet` chain because dependencies change in M2.

---

## 7. Pre-Milestone Protocol

Inherits §7 of the [v4 template](../templates/runbook-template_v_4_template.md). For this runbook the baseline test command is `cargo test -p secure_data --all-features`.

---

## 8. Post-Milestone Protocol

Inherits §8 of the [v4 template](../templates/runbook-template_v_4_template.md). Documentation update obligations are concrete in §18 below.

---

## 9. Background Context

### Current State

`secure_data` (crates/secure_data/) ships envelope encryption (`envelope.rs`), a cipher-agnostic `CryptoAlgorithm` enum (`algorithm.rs`) with two variants (`Aes256Gcm`, `XChaCha20Poly1305`), an `AlgorithmPolicy` for crypto-agility, KMS integrations behind feature flags (`vault`, `aws-kms`, `azure-kv`), and a `fips` feature gating the FIPS 140-2/3-track AEAD backend (`aws-lc-rs`). Password hashing is feature-gated (`password`). Mobile-secure-storage primitives are feature-gated (`mobile-storage`). Per-key rotation lives in `rotation.rs`. There is no post-quantum primitive support today; envelope wire format does not carry a version field; `EncryptionEnvelope` does not have room for a hybrid combiner-id byte.

### Problem

1. **No PQ posture** — critical-infrastructure consumers with ≥10-year secrecy windows must demonstrate a documented, executable PQ migration path. SunLit ships a security crate without one.
2. **No reserved enum slot** — adding a PQ variant later without a reservation in M1 creates a breaking change for `match` statements that depended on enum exhaustiveness, even with `#[non_exhaustive]`.
3. **Wire format has no version field** — adding a hybrid combiner-id byte requires a versioned envelope format. Bolting it on without an explicit version bump silently corrupts forward-compat semantics.
4. **`AlgorithmPolicy` cannot reject "v1-only" producers** once a PQ-only deployment exists — the policy needs a slot to express "this consumer requires v2 or higher" without a breaking signature change.

### Target Architecture

See §3 above. End state: `secure_data` consumers can opt into hybrid PQ envelope wrap via `cargo add secure_data --features pq`, the wire format documents version=1 (legacy AEAD) and version=2 (hybrid PQ), and old envelopes decrypt transparently on PQ-enabled and PQ-disabled builds alike.

### Key Design Principles

1. **Reserve before implement** — M1 reserves the enum slot and the wire-format version *before* M2 implements anything. Consumers that adopt the new envelope shape gain forward-compat without depending on M2 landing.
2. **No silent algorithm fallback** — a v2 envelope on a non-`pq` build returns `DataError::PqFeatureRequired`, never a silent failure or a downgrade to v1.
3. **Hybrid by default** — when `pq` is enabled, the default policy is hybrid (X25519 ⊕ ML-KEM-768), not ML-KEM-only. PQ-only is an explicit opt-in for migration finalization.
4. **OSS docs are first-class output** — every milestone produces rustdoc with at least one runnable example, README updates if user-facing surface changes, a CHANGELOG entry in user-facing language ("you can now …"), and dev-guide additions when a new capability is introduced.
5. **Release notes describe what consumers gain, not what we changed** — the CHANGELOG entry says "envelope wire format gains a `version` field; hybrid PQ KEM is now available behind `pq` feature." It does not say "refactored EncryptionEnvelope struct."
6. **FIPS-track is documented but not pursued** — per research synthesis (no CMVP cert covers ML-KEM as of 2026-05), `fips` × `pq` is honestly labelled "validation pending CMVP" and not "FIPS validated."

### What to Keep

- All existing `CryptoAlgorithm` variants and their wire-format identifiers.
- All existing `KeyProvider` implementations and their trait shape.
- All existing feature flags and their semantics.
- All existing `EncryptionEnvelope` round-trip semantics for old data.
- `secure_data` test layout and naming conventions.

### What to Change

- **`crates/secure_data/src/algorithm.rs`** — add `HybridX25519MlKem768` variant; extend `as_str()` and any From/TryFrom impls.
- **`crates/secure_data/src/envelope.rs`** — add `version: u8` field to `EncryptionEnvelope`; add `combiner_id: u8` for v2 envelopes; update (de)serialization with backwards-compat handling.
- **`crates/secure_data/src/lib.rs`** — declare new `pq` module behind `#[cfg(feature = "pq")]`.
- **`crates/secure_data/Cargo.toml`** — add `pq` feature entry; add ML-KEM crate dependency (gated).
- **`crates/secure_data/src/pq/{mod.rs,kem.rs,combiner.rs,sizes.rs}`** — NEW: hybrid KEM construction, HKDF-SHA-256 combiner, fixed-size constants.
- **`crates/secure_data/src/error.rs`** — add `PqFeatureRequired`, `PqUnavailable`, `AlgorithmRejectedByPolicy` variants.
- **`docs/dev-guide/secure-data.md`** — add PQ section with worked examples.
- **`docs/dev-guide/secure-data-pq.md`** — NEW: dedicated PQ dev guide.
- **`docs/slo/design/pq-migration-plan.md`** — NEW: authoritative migration plan.
- **`CHANGELOG.md`** — entry per milestone.
- **`README.md`** — update `secure_data` Feature Flags table to include `pq`.

### Global Red Lines

Inherits §9 of the [v4 template](../templates/runbook-template_v_4_template.md). Plus:

- No silent envelope-version downgrade. Ever.
- No KMS-side PQ integration in M1–M4 (out of scope; post-1.0).
- No claims of "FIPS validated PQ" in any documentation. Research confirmed no CMVP cert exists for ML-KEM as of 2026-05; honest labels only.
- No removal of AES-256-GCM as default. Default stays classical until a future runbook explicitly migrates it.

---

## 10. Carry-forward from prior retros

(Empty at runbook authoring time. `/slo-retro` populates this section as milestones complete.)

| Issue | Title | Suggested lane | Suggested milestone | Status |
|---|---|---|---|---|

---

## 11. BDD and Runtime Validation Rules

Inherits §11 of the [v4 template](../templates/runbook-template_v_4_template.md).

---

## 12. Dependency, Migration, and Refactor Policy

Inherits §12 of the [v4 template](../templates/runbook-template_v_4_template.md). Per-milestone dependency lists are explicit below.

---

## 13. Evidence Log Template

Per-milestone Evidence Logs are inlined in §17.

---

## 14. Self-Review Gate

Inherits §14 of the [v4 template](../templates/runbook-template_v_4_template.md). Plus runbook-specific:

- Did I keep AES-256-GCM as the default `CryptoAlgorithm`?
- Did I avoid claims of "FIPS-validated PQ"?
- Did I write CHANGELOG entries in user-facing language?
- Did I add a rustdoc example for every new public function?

---

## 15–16. Lessons / Completion Templates

Standard v4 (§15, §16). Lessons go to `docs/slo/lessons/pqd-m<N>.md`; completion summaries go to `docs/slo/completion/pqd-m<N>.md`.

---

## 17. Milestone Plan

### Milestone 1 — Migration plan + reserved `HybridX25519MlKem768` slot + envelope `version` field

**Goal**: Reserve the enum slot, version the wire format, and publish the authoritative PQ migration plan — without shipping any PQ implementation. After M1, downstream consumers can pin against an envelope shape that will not break when M2 lands.

**Context**: `crates/secure_data/src/algorithm.rs` defines `CryptoAlgorithm` with two variants. `crates/secure_data/src/envelope.rs` defines `EncryptionEnvelope` without a wire-format version. Adding a hybrid combiner-id byte later, without reserving today, costs a breaking change across every published envelope blob.

**Carmack-style reliability goal**: Bounded resources (encode ML-KEM-768 sizes as `const`); make invalid states unrepresentable (`combiner_id: u8` non-zero invariant for v2; deserialize rejects mismatched version+algorithm pairs).

**Important design rule**: The wire format is the contract. Choose the version-byte semantics now, write the on-disk layout to a worked-out diagram in the migration plan, and the M2 implementation has zero degrees of freedom on shape.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `EncryptionEnvelope` deserialization callers (existing v1 envelope blobs); `AlgorithmPolicy` callers |
| Outputs | New `CryptoAlgorithm::HybridX25519MlKem768` enum slot; new `version: u8` field on `EncryptionEnvelope`; new `combiner_id: u8` field for v2 (default `0xFF` reserved-not-used in v1); migration plan doc |
| Interfaces touched | `secure_data::algorithm::CryptoAlgorithm`, `secure_data::envelope::EncryptionEnvelope` (de)ser, `secure_data::error::DataError` (new variants) |
| Files allowed to change | `crates/secure_data/src/algorithm.rs`, `crates/secure_data/src/envelope.rs`, `crates/secure_data/src/error.rs`, `crates/secure_data/src/lib.rs` (re-exports only), `docs/slo/design/pq-migration-plan.md` (NEW), `docs/dev-guide/secure-data.md` (PQ-readiness section), `CHANGELOG.md`, `README.md` (Feature Flags table touch only if needed), `crates/secure_data/tests/pqd_m1_envelope_versioning.rs` (NEW) |
| Files to read before changing anything | `crates/secure_data/src/algorithm.rs`, `crates/secure_data/src/envelope.rs`, `crates/secure_data/src/error.rs`, `crates/secure_data/Cargo.toml`, [`docs/slo/research/pq-readiness-secure-data/synthesis.md`](../research/pq-readiness-secure-data/synthesis.md), [`docs/slo/research/pq-readiness-secure-data/dossier.md`](../research/pq-readiness-secure-data/dossier.md) |
| New files allowed | `docs/slo/design/pq-migration-plan.md`, `crates/secure_data/tests/pqd_m1_envelope_versioning.rs` |
| New dependencies allowed | `none` |
| Migration allowed | `yes` — wire-format version field; backwards-compat strategy: deserialization defaults missing `version` to `1`, missing `combiner_id` to `0`. Round-trip test against committed v1 fixture mandatory. |
| Compatibility commitments | All existing v1 envelope blobs deserialize and decrypt identically. AES-256-GCM remains the default `CryptoAlgorithm`. No `KeyProvider` impl changes. |
| Resource bounds introduced/changed | Constants for ML-KEM-768 sizes added to a new `secure_data::pq::sizes` module skeleton (no impl yet): `ML_KEM_768_CIPHERTEXT_LEN: usize = 1088`, `ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184`, `ML_KEM_768_SHARED_SECRET_LEN: usize = 32`, `X25519_SHARE_LEN: usize = 32`, `HKDF_SHA256_OUTPUT_LEN: usize = 32` |
| Invariants/assertions required | (1) Deserialized v1 envelopes always have `version == 1` and `combiner_id == 0`. (2) `combiner_id` field is reserved-zero in v1 and rejected at deserialize if non-zero. (3) `CryptoAlgorithm::HybridX25519MlKem768` constructed without `pq` feature returns `DataError::PqUnavailable` from any encrypt path (skeleton; M2 fills the encrypt path). |
| Debugger / inspection expectation | Wire format is human-inspectable: pretty-print of `EncryptionEnvelope` shows `version`, `combiner_id`, `algorithm` clearly; integration test prints the v1 fixture vs. v2 layout side-by-side under `--nocapture` |
| Static analysis gates | `cargo fmt --all -- --check`; `cargo clippy -p secure_data --all-targets --all-features -- -D warnings`; `cargo test -p secure_data --all-features`; `cargo audit && cargo deny check && cargo vet` |
| Forbidden shortcuts | No silent default for missing `combiner_id` in a v2 envelope. No "TODO: implement PQ in M2" comments in production code paths. No `#[allow(dead_code)]` on the new enum variant — it is a real public API. |
| Data classification | `Confidential` — envelope plaintext is by definition sensitive; this milestone touches the wire format but not plaintext handling. |
| Proactive controls in play | `C2 secure_data::envelope` (Leverage Security Frameworks and Libraries → cryptographic agility). |
| Abuse acceptance scenarios | `tm-pqd-abuse-1`: Attacker forges a v2 envelope on a non-`pq` build → must return `PqFeatureRequired`, never crash, never decrypt as v1. `tm-pqd-abuse-2`: Attacker submits a v1 envelope with non-zero `combiner_id` → deserialize must reject with structured error. |

#### Out of Scope / Must Not Do

- Implementing the actual hybrid KEM (M2).
- Adding `pq` feature to `Cargo.toml` (M2).
- Modifying any `KeyProvider` implementation.
- Touching `password`, `mobile-storage`, or other unrelated feature paths.
- Producing release-tagged crates.io publish (post-runbook).

#### Pre-Flight

1. Complete §7 of the v4 template.
2. Read the research synthesis for ML-KEM crate / wire-format guidance.
3. Read `crates/secure_data/src/{algorithm,envelope,error}.rs`.
4. Copy the Evidence Log template into a milestone working note.
5. Restate constraints: enum slot reserved (no impl), wire-format versioned, migration plan written, no new dependencies, no behavior change for v1 envelopes.

#### Files Allowed To Change

| File | Planned Change |
|---|---|
| `crates/secure_data/src/algorithm.rs` | Add `HybridX25519MlKem768` variant; extend `as_str()`; mark with `#[doc(hidden)]` or document explicitly that the implementation lands in M2 |
| `crates/secure_data/src/envelope.rs` | Add `version: u8` field (default 1); add `combiner_id: u8` field (zero in v1); update Serialize/Deserialize with backwards-compat for missing fields |
| `crates/secure_data/src/error.rs` | Add `DataError::PqUnavailable`, `DataError::PqFeatureRequired`, `DataError::AlgorithmRejectedByPolicy` |
| `crates/secure_data/src/lib.rs` | Re-export new error variants; declare `pub mod pq;` placeholder behind a doc-only stub for M1 (size constants only, no impl) |
| `crates/secure_data/src/pq/sizes.rs` | NEW: `pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;` etc. — public, doc'd |
| `crates/secure_data/tests/pqd_m1_envelope_versioning.rs` | NEW: BDD scenarios per §17.M1 BDD table |
| `docs/slo/design/pq-migration-plan.md` | NEW: authoritative migration plan, ML-KEM crate decision (`ml-kem` v0.3.0 per research), wire-format diagram, threat-model framing, FIPS-track honest labelling |
| `docs/dev-guide/secure-data.md` | Add "Post-Quantum Readiness (M1: reserved; M2+: implementation)" section with example showing the v2 envelope shape |
| `CHANGELOG.md` | Entry: "Reserved `CryptoAlgorithm::HybridX25519MlKem768` slot and added `version`/`combiner_id` fields to `EncryptionEnvelope` for forward-compat with hybrid PQ KEM (implementation in next release)." |
| `README.md` | If `secure_data` Feature Flags table lists future flags, add a "(planned)" row for `pq` with link to migration plan; otherwise no change |
| `.gitignore` | (no change expected) |

#### Step-by-Step

1. Read research synthesis + dossier; confirm `ml-kem` v0.3.0 + concat-HKDF wire format are the locked decisions.
2. Write BDD test stubs in `crates/secure_data/tests/pqd_m1_envelope_versioning.rs`.
3. Write the migration plan doc skeleton.
4. Add error variants.
5. Add enum variant; add (de)serialization round-trip + backwards-compat handling.
6. Add `pq::sizes` module with constants only.
7. Run formatter, lint, tests; iterate until green.
8. Fill out the migration plan doc body (decisions, threat model framing, FIPS posture).
9. Update CHANGELOG and dev-guide.
10. Verify v1 fixture round-trip (committed binary or hex-encoded fixture file).
11. Run smoke tests + Self-Review Gate.

#### BDD Acceptance Scenarios

**Feature: envelope wire format versioning**

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| v1 envelope round-trip | happy path | a fixture v1 envelope blob from before this change | deserialize then serialize | byte-identical output |
| v1 envelope without version field | backward compatibility | a serialized v1 envelope produced by the prior crate version | deserialize | `version` defaults to 1, `combiner_id` defaults to 0, decrypt succeeds |
| v1 envelope with non-zero combiner_id | invalid input | a hand-crafted v1 envelope with `combiner_id=42` | deserialize | returns structured `DataError::EnvelopeMalformed` |
| New enum variant constructed without `pq` | resource bound / abuse case | `pq` feature disabled | call any encrypt with `CryptoAlgorithm::HybridX25519MlKem768` | returns `DataError::PqUnavailable` |
| AlgorithmPolicy rejects mismatched version | assertion violation | policy says "minimum version=2" | encrypt with `Aes256Gcm` (which produces v1) | returns `DataError::AlgorithmRejectedByPolicy` |
| migration plan exists and is non-empty | empty state | runbook M1 just started | check `docs/slo/design/pq-migration-plan.md` | exists; ≥3 sections (Decisions / Wire Format / Threat Model); cites research synthesis |

#### Regression Tests

- All existing `secure_data` tests (`cargo test -p secure_data --all-features`) remain green.
- Existing `e2e_*` tests for envelope encryption decrypt unchanged.
- KAT tests for AEAD unchanged.

#### Compatibility Checklist

- [ ] All existing v1 envelope round-trip tests pass.
- [ ] AES-256-GCM remains the default `CryptoAlgorithm`.
- [ ] No `KeyProvider` impl changes.
- [ ] Existing feature flags (`vault`, `aws-kms`, `fips`, `password`, `azure-kv`, `mobile-storage`) unchanged.
- [ ] No public type rename in `algorithm` / `envelope` modules.

#### E2E Runtime Validation

**File**: `crates/secure_data/tests/pqd_m1_envelope_versioning.rs`

| E2E Test | What It Proves | Pass Criteria |
|---|---|---|
| `e2e_v1_fixture_round_trip` | committed v1 fixture deserializes + decrypts identically | byte-equal plaintext recovery |
| `e2e_pq_unavailable_without_feature` | constructing a Hybrid envelope without `pq` feature is a structured error | `DataError::PqUnavailable` returned, no panic |

#### Smoke Tests

- [ ] `cargo build -p secure_data` (no features) succeeds.
- [ ] `cargo build -p secure_data --all-features` succeeds.
- [ ] `cargo doc -p secure_data --no-deps` produces valid docs with the new enum variant documented.
- [ ] `cargo expand -p secure_data` shows the new fields without unsafe expansion.
- [ ] `git status` shows no untracked test artifacts.
- [ ] `.gitignore` covers the new test fixture if any was generated.

#### Evidence Log

| Step | Command / Check | Expected Result | Actual | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Baseline tests | `cargo test -p secure_data --all-features` | green | | | |
| BDD tests created | `crates/secure_data/tests/pqd_m1_envelope_versioning.rs` | fail for expected reason (no impl yet) | | | |
| E2E stubs created | same file | fail for expected reason | | | |
| Implementation | enum + envelope fields + error variants + migration plan | contract satisfied | | | |
| Formatter | `cargo fmt --all -- --check` | clean | | | |
| Typecheck | `cargo build --workspace` | clean | | | |
| Static analyzer | `cargo clippy -p secure_data --all-targets --all-features -- -D warnings` | clean | | | |
| Dependency audit | `cargo audit && cargo deny check && cargo vet` | pass | | | (no deps changed in M1) |
| Full tests | `cargo test --workspace --all-features` | green | | | |
| E2E runtime | `cargo test -p secure_data --test 'pqd_m1_*'` | green | | | |
| Build/boot | `cargo build --workspace` | clean | | | |
| Smoke tests | per smoke list above | all checked | | | |
| Resource-bound verification | size constants compile + assert | constants present | | | |
| Invariant verification | combiner_id-zero invariant test passes | yes | | | |
| Debugger / state inspection | `--nocapture` BDD output shows v1/v2 layouts | hypothesis confirmed | | | |
| Test artifact cleanup | `git status` | clean | | | |
| `.gitignore` review | check for generated fixtures | current | | | |
| Compatibility checks | per checklist above | green | | | |

#### Definition of Done

- All BDD scenarios pass.
- E2E runtime tests green.
- Existing test suite remains green.
- Formatter, typecheck, static analysis, audit chain pass.
- All listed compatibility commitments verified.
- Migration plan doc complete with all 3 required sections (Decisions / Wire Format / Threat Model + FIPS).
- CHANGELOG entry written in user-facing language.
- rustdoc example added for `HybridX25519MlKem768` and the new envelope fields.
- Lessons file at `docs/slo/lessons/pqd-m1.md` written.
- Completion summary at `docs/slo/completion/pqd-m1.md` written.
- Milestone Tracker in this file updated.

#### Post-Flight

- **ARCHITECTURE.md**: add a note in the `secure_data` section describing the new envelope versioning (one paragraph, link to migration plan).
- **README.md**: update Feature Flags table for `secure_data` if `(planned) pq` row helps consumers; otherwise skip.
- **Other docs**: `docs/dev-guide/secure-data.md` PQ-readiness section.

---

### Milestone 2 — Hybrid X25519 + ML-KEM-768 KEM behind `pq` feature; envelope encryption end-to-end

**Goal**: Implement the hybrid KEM construction (X25519 || ML-KEM-768, fed through HKDF-SHA-256) behind a `pq` feature flag (off by default), enabling `encrypt_for_storage` and `decrypt_for_use` to round-trip a v2 envelope when the feature is on.

**Context**: M1 reserved the slot and the wire format; M2 fills the implementation. Per research, `RustCrypto/ml-kem` v0.3.0 is the locked dependency; concat-HKDF is the locked wire format; `combiner_id = 0x01` for "X25519+ML-KEM-768 / HKDF-SHA-256 / TLS-style concat" — leave 0xFF reserved for future X-Wing or QSF combiner adoption.

**Carmack-style reliability goal**: Static analysis mandatory (cargo deny verifies the new dep license); KAT vectors for ML-KEM-768 from the FIPS 203 reference; assertions on shared-secret length; bounded resources (no allocation growth beyond the fixed primitive sizes from M1).

**Important design rule**: The hybrid construction is symmetric to existing `encrypt_for_storage`/`decrypt_for_use` — a new internal helper `pq::hybrid_wrap_data_key` and `pq::hybrid_unwrap_data_key` plug into the existing envelope flow. Application code never touches ML-KEM directly.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `encrypt_for_storage`/`encrypt_with_policy` callers; `decrypt_for_use` callers; `KeyProvider::wrap_data_key` (existing trait) |
| Outputs | A v2 `EncryptionEnvelope` containing X25519 share + ML-KEM-768 ciphertext + AEAD-wrapped data key |
| Interfaces touched | `secure_data::pq::{hybrid_encapsulate, hybrid_decapsulate}` (NEW), envelope encrypt/decrypt internals (gated on `pq` feature) |
| Files allowed to change | `crates/secure_data/src/pq/{mod.rs,kem.rs,combiner.rs}` (NEW), `crates/secure_data/src/envelope.rs` (gated branches), `crates/secure_data/src/algorithm.rs` (encrypt/decrypt dispatch for new variant), `crates/secure_data/Cargo.toml` (add `pq` feature, gated `ml-kem` dep, gated `x25519-dalek` dep, gated `hkdf` and `sha2` if not already present), `crates/secure_data/tests/pqd_m2_hybrid_kem.rs` (NEW), `crates/secure_data/tests/fixtures/ml_kem_768_kat.bin` (NEW: pinned KAT fixture), `docs/dev-guide/secure-data-pq.md` (NEW: dedicated dev guide), `CHANGELOG.md`, `README.md` |
| Files to read before changing anything | M1 outputs (algorithm.rs, envelope.rs, error.rs, pq-migration-plan.md), [research dossier](../research/pq-readiness-secure-data/dossier.md), [research synthesis](../research/pq-readiness-secure-data/synthesis.md), `crates/secure_data/Cargo.toml` |
| New files allowed | `crates/secure_data/src/pq/{mod.rs,kem.rs,combiner.rs}`, `crates/secure_data/tests/pqd_m2_hybrid_kem.rs`, `crates/secure_data/tests/fixtures/ml_kem_768_kat.bin`, `docs/dev-guide/secure-data-pq.md` |
| New dependencies allowed | `ml-kem = "0.3"` (gated on `pq`), `x25519-dalek = "2"` (gated on `pq`), `hkdf = "0.12"` (gated on `pq` if not already present), `sha2 = "0.10"` (gated on `pq` if not already present). Each dep requires a `cargo deny` license check + `cargo vet` audit row. Justification per dep: `ml-kem` — RustCrypto-maintained pure-Rust ML-KEM-768 (FIPS 203). `x25519-dalek` — production-tested, no `unsafe` in core path. `hkdf`+`sha2` — RustCrypto-maintained, well-audited, no `unsafe`. |
| Migration allowed | `no` |
| Compatibility commitments | Default builds (no features) compile and behave identically. AES-256-GCM and XChaCha20-Poly1305 paths untouched. v1 envelopes decrypt unchanged with or without `pq`. |
| Resource bounds introduced/changed | All KEM ops use the fixed-size constants from M1's `pq::sizes`. Assertions: shared secret = 32 bytes; ciphertext = 1088 bytes; HKDF output = 32 bytes |
| Invariants/assertions required | (1) Hybrid encapsulation never returns a zero shared secret. (2) HKDF input never re-uses an X25519 share (random per call). (3) `combiner_id == 0x01` for every v2 envelope produced by this code path. (4) Decapsulation rejects mismatched ML-KEM ciphertext sizes with `DataError::EnvelopeMalformed`. |
| Debugger / inspection expectation | KAT fixture decoded under `--nocapture` shows the X25519 share, ML-KEM ciphertext bytes, HKDF output, AEAD ciphertext — all bounded sizes. Inspection includes `cargo expand` of the new `pq` module to confirm no unsafe blocks expand from the new dep usage. |
| Static analysis gates | All gates from §4.2; **plus** `cargo deny check licenses` confirming all new deps are MIT or Apache-2.0; **plus** `cargo geiger -p secure_data --features pq` recorded as the new official PQ-feature unsafe number. |
| Forbidden shortcuts | No "stub" KEM that just returns zeros. No `unwrap()` on KEM operations in production paths. No silent fallback if `ml-kem` errors. No `#[allow(unsafe_code)]` to enable an unsafe block in `pq` module — `forbid(unsafe_code)` remains crate-wide. |
| Data classification | `Confidential` |
| Proactive controls in play | `C2 secure_data::envelope` (Leverage Security Frameworks and Libraries), `C8 secure_data::pq` (Protect Data Everywhere — including in transit to a KMS/disk under PQ assumptions). |
| Abuse acceptance scenarios | `tm-pqd-abuse-3`: Attacker tampers an ML-KEM ciphertext byte → decapsulation fails with structured error, no decrypt, no panic. `tm-pqd-abuse-4`: Attacker submits a v2 envelope with `combiner_id=0xFF` (reserved-future) → returns `DataError::CombinerNotSupported`, never decrypts as `combiner_id=0x01`. `tm-pqd-abuse-5`: Attacker submits a malformed `pq`-feature envelope on a non-`pq` build → returns `DataError::PqFeatureRequired`. |

#### Out of Scope / Must Not Do

- KMS provider PQ integration (e.g. AWS KMS GenerateDataKey with hybrid KEM) — post-1.0.
- ML-DSA / SLH-DSA signatures — separate runbook.
- Replacing AEAD with a PQ AEAD — ML-KEM is for KEM, not for the AEAD itself.
- Performance tuning beyond default crate settings.

#### Pre-Flight, Files Allowed To Change, Step-by-Step, BDD, Regression, Compatibility, E2E, Smoke, Evidence Log, Definition of Done, Post-Flight

(Same shape as M1 — covers: read M1 lessons, run baseline, write BDD scenarios first including `tm-pqd-abuse-3..5`, implement, format, lint, audit (license + geiger), test, smoke, gate.)

**BDD Acceptance Scenarios** (key rows — abuse-case rows mandatory):

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| v2 envelope round-trip with `pq` feature | happy path | `pq` feature on; provider returns a wrapped data key | encrypt then decrypt | plaintext recovered byte-identical |
| KAT vector matches FIPS 203 | happy path | committed KAT fixture | run hybrid_decapsulate against it | shared secret matches expected bytes |
| Tampered ML-KEM ciphertext | abuse case (`tm-pqd-abuse-3`) | a v2 envelope with one byte flipped in the ML-KEM ciphertext | decrypt | returns `DataError::EnvelopeMalformed` or `DataError::DecapsulationFailed`; no decrypt |
| Reserved combiner_id | abuse case (`tm-pqd-abuse-4`) | a v2 envelope with `combiner_id=0xFF` | decrypt | returns `DataError::CombinerNotSupported`; no fallback to 0x01 |
| `pq` envelope on non-`pq` build | abuse case (`tm-pqd-abuse-5`) | binary built without `pq` | attempt to decrypt a v2 envelope | returns `DataError::PqFeatureRequired` |
| `cargo deny licenses` for new deps | compatibility | new deps added | run `cargo deny check licenses` | all MIT or Apache-2.0 |
| `cargo geiger` for `pq` feature | resource bound | `pq` feature on | run `cargo geiger -p secure_data --features pq` | unsafe count recorded as artifact; documented in CHANGELOG |

(Full milestone template per §17 of the v4 template; Evidence Log inlined as in M1; full Definition of Done verbatim per the v4 template plus the runbook-specific items.)

---

### Milestone 3 — Backwards-compat decrypt, downgrade-attack regression tests, and algorithm-policy enforcement

**Goal**: Lock the cross-version compatibility matrix: every combination of (v1 producer, v2 producer) × (`pq` consumer, non-`pq` consumer) behaves correctly — round-trip where it should, structured error where it should, never silent downgrade.

**Context**: M1+M2 produce both envelope shapes. Without M3, an attacker who can substitute envelopes between producer and consumer could mount a downgrade attack ("force the consumer to decrypt a v1 envelope when policy says v2-only"). M3 codifies the test matrix and lands `AlgorithmPolicy::min_version` as a real enforcement boundary.

**Carmack-style reliability goal**: Make invalid states unrepresentable (`AlgorithmPolicy` accepts a `min_version: u8`, not a free-form string); assertions on policy outcomes; static analysis remains clean.

**Important design rule**: The compatibility matrix is the contract. M3's BDD table enumerates every cell.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Files allowed to change | `crates/secure_data/src/algorithm.rs` (`AlgorithmPolicy::min_version`), `crates/secure_data/src/envelope.rs` (policy enforcement at decrypt boundary), `crates/secure_data/src/error.rs` (already has the variants from M1), `crates/secure_data/tests/pqd_m3_compat_matrix.rs` (NEW), `docs/dev-guide/secure-data-pq.md`, `CHANGELOG.md` |
| New dependencies allowed | `none` |
| Compatibility commitments | All M1+M2 BDD scenarios remain green. Existing `AlgorithmPolicy` callers compile unchanged. Default policy (no min_version set) accepts v1 and v2. |
| Resource bounds introduced/changed | (none new; reuses M1+M2) |
| Invariants/assertions required | (1) `AlgorithmPolicy::min_version=2` rejects every v1 envelope at decrypt with `AlgorithmRejectedByPolicy`. (2) Default policy accepts v1 and v2 round-trip. (3) No code path exists where a tampered envelope-version byte produces a successful decrypt. |
| Abuse acceptance scenarios | `tm-pqd-abuse-6`: Downgrade attack — attacker substitutes a v1 envelope where v2 is expected by policy → returns `AlgorithmRejectedByPolicy`. `tm-pqd-abuse-7`: Version-byte tampering — attacker flips `version=2` to `version=1` on a v2 envelope → AEAD authentication fails, no decrypt. |
| Data classification | `Confidential` |
| Proactive controls in play | `C2`, `C5 secure_data::AlgorithmPolicy` (Validate All Inputs — including envelope-version policy as a "safe input"). |

(Full milestone template; BDD enumerates the 4-cell compatibility matrix + 2 abuse cases; Evidence Log inlined; DoD per v4.)

---

### Milestone 4 — FIPS-track readiness note + `fips` × `pq` interaction documentation

**Goal**: Document the FIPS-track posture honestly: no CMVP cert covers ML-KEM as of 2026-05; the `fips` + `pq` build is labelled "validation pending CMVP"; the migration plan describes the trigger conditions for re-engaging the FIPS path.

**Context**: Per research synthesis, AWS-LC FIPS 3.0 is on CMVP "modules in process" since 2024-12; no public ETA. SunLit consumers in regulated environments need to know what `fips` + `pq` builds can and cannot claim *today*.

**Carmack-style reliability goal**: Documentation precision; no "FIPS validated PQ" claim anywhere; static analysis confirms no code path uses an unvalidated primitive when `fips` feature is on (test: building with `--features fips,pq` either compiles to a clearly-labelled non-validated path or refuses with a documented error).

**Important design rule**: Honest labels beat aspirational claims. The `fips` feature has historically meant "FIPS 140-{2,3} validated AEAD backend." Adding `pq` does not extend that property; the build label must reflect that.

**Refactor budget**: `No refactor permitted beyond direct implementation`.

#### Contract Block

| Field | Value |
|---|---|
| Files allowed to change | `crates/secure_data/src/lib.rs` (rustdoc only — `fips` × `pq` interaction note), `crates/secure_data/src/pq/mod.rs` (compile-time warning or runtime label when both features are on), `docs/slo/design/pq-migration-plan.md` (FIPS-track section), `docs/dev-guide/secure-data-pq.md` (FIPS section), `README.md` (`secure_data` Feature Flags table footnote), `CHANGELOG.md` |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | M1+M2+M3 all remain green. `fips`-only builds (without `pq`) unchanged. `fips`+`pq` builds compile and behave identically to M2's `pq` build but additionally emit a runtime metadata field `pq_fips_status: "pending_cmvp"` in any envelope produced (visible in `Debug` output, not in wire format). |
| Resource bounds introduced/changed | (none) |
| Invariants/assertions required | (1) `fips`+`pq` build never emits "FIPS validated" string. (2) Trigger condition for promoting `pq` to FIPS-validated is a documented procedure (CMVP cert ID + AWS-LC version + opt-in feature flag). |
| Abuse acceptance scenarios | `tm-pqd-abuse-8`: Operator misreads compatibility — believes `fips`+`pq` is FIPS-validated → README/dev-guide/inline rustdoc explicitly state validation-pending, and CI lint blocks any "FIPS validated PQ" string in docs/changelog. |
| Data classification | `Public` (documentation milestone). |
| Proactive controls in play | (documentation milestone — no new control surface). |

(Full milestone template; BDD enumerates label-correctness scenarios; Evidence Log; DoD per v4.)

#### Out of Scope / Must Not Do

- Engaging the actual CMVP path.
- Publishing any "FIPS validated PQ" claim.
- Adding a runtime check that requires network access to verify CMVP status.

---

## 18. Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 1 | Note in `secure_data` section about envelope wire-format versioning | Feature Flags table footnote re: planned `pq` | — | `docs/dev-guide/secure-data.md`, `docs/slo/design/pq-migration-plan.md` (NEW) |
| 2 | Update `secure_data` section with `pq` feature | Add `pq` row to Feature Flags table | Cover any KAT-fixture artifacts | `docs/dev-guide/secure-data-pq.md` (NEW), `CHANGELOG.md` |
| 3 | (no change) | Compat matrix link in `secure_data` notes | — | `docs/dev-guide/secure-data-pq.md` extended; CHANGELOG |
| 4 | (no change) | Footnote on `fips`+`pq` interaction | — | `pq-migration-plan.md` FIPS section, `secure-data-pq.md` FIPS section, CHANGELOG |

---

## 19. Optional Fast-Fail Review Prompt for Agents

> Restate the milestone goal, allowed files, forbidden changes, compatibility requirements, dependency/migration rules, required tests, required runtime validation, resource bounds, invariants, static-analysis gates, debugger expectation, and the exact Definition of Done. Then list the smallest implementation approach that satisfies the contract without widening scope. Cite the research synthesis row for every primitive choice and the migration plan section for every wire-format decision.

---

## 20. Source Basis

This runbook is a v4 instance authored against [`docs/slo/templates/runbook-template_v_4_template.md`](../templates/runbook-template_v_4_template.md). Research basis: [`docs/slo/research/pq-readiness-secure-data/dossier.md`](../research/pq-readiness-secure-data/dossier.md) (29 sources; `incomplete:true` due to no published audit and no CMVP cert; recommendations: `RustCrypto/ml-kem v0.3.0`, concat+HKDF wire format, monitor-only FIPS posture). Idea basis: [`docs/slo/idea/pq-readiness-secure-data.md`](../idea/pq-readiness-secure-data.md).

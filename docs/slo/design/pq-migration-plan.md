---
name: pq-migration-plan
authored: 2026-05-05
runbook: pq-readiness-secure-data
runbook_milestone: M2
research_basis: docs/slo/research/pq-readiness-secure-data/synthesis.md
status: locked-in (M1); implemented through M2
---

# Post-Quantum Migration Plan — `secure_data`

**Status (2026-05-06):** M2 is implemented behind `--features pq`; the locked X25519 + ML-KEM-768 / HKDF-SHA-256 v2 envelope wrap is now executable.

> **One-line summary.** `secure_data` has gained a hybrid X25519 + ML-KEM-768 / HKDF-SHA-256 KEM behind a `pq` feature flag. M1 reserved the public surface (enum slot, envelope `combiner_id` field, error variants, size constants); M2 ships the implementation; M3 lands the cross-version compatibility matrix; M4 documents the FIPS-track posture honestly.

---

## 1. Motivation

Critical-infrastructure consumers with secrecy windows of 10 years or more must demonstrate a documented, executable post-quantum migration path. A "harvest now, decrypt later" adversary recording today's classical envelopes can decrypt them at a future date once a sufficiently capable quantum computer exists. The migration target is therefore the *key wrap* — the data-key encryption — not the AEAD itself: AES-256-GCM and XChaCha20-Poly1305 remain Grover-resistant under credible models, but the key transport must shift to a primitive the adversary cannot break in advance.

The chosen path is a **hybrid** construction (classical X25519 ⊕ post-quantum ML-KEM-768) rather than a PQ-only construction, because:

1. ML-KEM-768 was finalised as **FIPS 203 in 2024**, but no FIPS 140-3 cryptographic module covers it as of 2026-05 (AWS-LC FIPS 3.0 is on CMVP "modules in process" since 2024-12 with no public ETA, per the research dossier). Hybrid keeps the classical X25519 leg in the security argument so a hypothetical future ML-KEM cryptanalysis cannot retroactively compromise everything.
2. NIST and the CFRG have recommended hybrid KEMs for the migration period in multiple drafts and statements; production deployments at AWS, Cloudflare, and Google in 2024–2025 have followed this pattern.
3. Hybrid is a strict superset of either leg's security: an attacker must break **both** X25519 and ML-KEM-768 to recover the wrap key.

---

## 2. Locked-in decisions

These decisions come from the research dossier (29 sources; pinned 2026-05-05) and are not re-litigated in M2:

| Decision | Value | Rationale |
|---|---|---|
| Primary ML-KEM crate (default `pq`) | [`RustCrypto/ml-kem`](https://github.com/RustCrypto/formats/tree/master/ml-kem) v0.3.0 | Pure-Rust; matches `secure_data`'s existing no-FFI posture; well-audited maintainership; `forbid(unsafe_code)`-compatible |
| FIPS-track ML-KEM crate (future `pq-aws-lc` feature) | [`aws-lc-rs`](https://github.com/aws/aws-lc-rs) | Aligns with the existing `fips` feature; AWS-LC is on the CMVP "modules in process" list — when validated, this becomes the FIPS path |
| Wire format | TLS-style concatenation `(ML-KEM_ct ‖ X25519_share)` with shared secrets fed through HKDF-SHA-256 | Aligns with `draft-ietf-tls-hybrid-design` consensus as of 2026-Q1; readable, debuggable, no exotic combiner needed |
| Combiner | HKDF-SHA-256 with deterministic info string `"sunlit-pq-x25519-ml-kem-768/v1"` | Standardised, audited, fits in the pure-Rust budget |
| Symmetric AEAD | AES-256-GCM (the existing default) — *unchanged* | The PQ migration affects key wrap, not the AEAD |
| Combiner identifier | `0x01` for the M2 combiner; `0x80–0xFE` reserved for future combiners (X-Wing, CFRG QSF); `0xFF` permanent fail-closed sentinel | Forward-compat for adopting newer combiners without a breaking wire-format change |
| FIPS-track posture for M4 | **Monitor only.** No CMVP cert covers ML-KEM as of 2026-05; `fips` × `pq` builds are honestly labelled "validation pending CMVP" | No false claims of FIPS-validated PQ |

---

## 3. Wire format

### 3.1 Pre-existing envelope shape (classical, v1)

```text
EnvelopeEncrypted {
    version:          "1"
    algorithm:        "AES-256-GCM" | "XChaCha20-Poly1305"
    key_alias:        <string>
    key_version:      <string>
    wrapped_data_key: <bytes>     // KEK-wrapped DEK
    nonce:            <bytes>     // 12 (AES-GCM) or 24 (XChaCha20) bytes
    ciphertext:       <bytes>     // AEAD-protected plaintext
    aad:              <bytes>     // deterministic envelope header bytes
    // (combiner_id absent in pre-M1 envelopes; defaults to None on deserialize)
}
```

### 3.2 M1: shape evolution (forward-compatible)

M1 adds **one optional field**:

```text
EnvelopeEncrypted {
    ...all v1 fields...
    combiner_id:      Option<u8>   // None for classical; Some(id) for hybrid
}
```

`#[serde(default, skip_serializing_if = "Option::is_none")]` ensures:

- Pre-M1 envelopes (no `combiner_id` field on the wire) deserialize to `combiner_id == None`.
- Classical envelopes serialised post-M1 do **not** emit a `combiner_id` field — bytes-per-envelope unchanged for the dominant case.
- Hybrid envelopes (M2 onward) emit `Some(0x01)` explicitly.

### 3.3 M2 hybrid envelope

```text
EnvelopeEncrypted {
    version:          "2"
    algorithm:        "X25519+ML-KEM-768/HKDF-SHA-256"
    key_alias:        <string>
    key_version:      <string>
    wrapped_data_key: <bytes>     // = ML-KEM_ct ‖ X25519_share ‖ AES-GCM(KEK_HKDF, DEK)
    nonce:            <bytes>     // 12 bytes (AES-GCM nonce for the inner data-key wrap)
    ciphertext:       <bytes>     // unchanged: AES-256-GCM-protected plaintext
    aad:              <bytes>     // deterministic envelope header bytes (now binds combiner_id)
    combiner_id:      Some(0x01)  // X25519 + ML-KEM-768 / HKDF-SHA-256
}
```

The inner construction in `wrapped_data_key`:

```text
ML-KEM-768 ciphertext  (1088 bytes)  ─┐
X25519 share           (  32 bytes)  ─┤── concat ──┐
                                                    │
                                                    ▼
                                          HKDF-SHA-256
                                              │
                                              ▼
                                   wrap key (32 bytes, AES-256-GCM key)
                                              │
                                              ▼
                                AES-GCM-wrapped DEK   (variable bytes)
```

The recipient performs ML-KEM decapsulation + X25519 ECDH, concatenates the shared secrets in the same order, runs HKDF-SHA-256 with the locked info string, and unwraps the DEK with AES-256-GCM.

### 3.4 Combiner identifier table

| Value | Combiner | Status |
|---|---|---|
| `0x00` | Reserved (never on the wire — equivalent to `None`) | accepted by `validate_structure` for legacy serialisers; not emitted |
| `0x01` | **X25519 + ML-KEM-768 / HKDF-SHA-256** | M2 default |
| `0x02` – `0x7F` | Reserved for future combiners (M3+) | rejected as `AlgorithmRejectedByPolicy` until explicitly recognised |
| `0x80` – `0xFE` | Reserved-future range (X-Wing, CFRG QSF, etc.) | rejected as `AlgorithmRejectedByPolicy` |
| `0xFF` | **Permanent fail-closed sentinel** | always rejected; never emitted by any version of this crate |

---

## 4. Threat model framing

The migration plan addresses the following threat classes:

### 4.1 In scope

- **Harvest now, decrypt later** (10-year secrecy class). Hybrid construction means an adversary recording M2-era envelopes today must break X25519 (Shor on ECDLP) **and** ML-KEM-768 (lattice cryptanalysis) to recover plaintext, even decades later.
- **Downgrade attack**: an attacker who can substitute envelopes between producer and consumer cannot force a downgrade from v2 hybrid to v1 classical, because:
  1. M3's `AlgorithmPolicy::min_version` lets a consumer require v2-or-higher envelopes; v1 envelopes return `AlgorithmRejectedByPolicy`.
  2. The `aad` bytes bind the algorithm string; any tampering fails AEAD authentication.
- **Combiner substitution**: an attacker who flips `combiner_id` on a v2 envelope from `0x01` to `0xFF` (fail-closed) or any reserved-future value gets `AlgorithmRejectedByPolicy` from `validate_structure` before any cryptographic operation. No silent acceptance.
- **Build-skew misuse**: a v2 envelope sent to a non-`pq`-feature build returns `PqFeatureRequired` from `validate_structure` before any cryptographic operation. No silent fallback to classical.

### 4.2 Out of scope (documented residual risk)

- **Side-channel attacks on the ML-KEM implementation.** RustCrypto `ml-kem` v0.3.0 is constant-time per its specification, but no Rust implementation has the same level of hardware-level side-channel hardening as some C libraries with HSM-grade timing analysis. Mitigation path: when AWS-LC FIPS-validated ML-KEM lands, the `pq-aws-lc` feature becomes the recommended path for high-assurance environments; until then, this is a documented residual risk.
- **Post-quantum signature schemes (ML-DSA, SLH-DSA).** Out of scope for this runbook. Signatures require a separate runbook because key sizes and migration patterns differ materially from KEMs.
- **KMS-side hybrid wrap.** AWS KMS, HashiCorp Vault Transit, and Google Cloud KMS do not yet support PQ or hybrid wrapping primitives at the KMS API level (verified 2026-05). M2 performs the hybrid wrap **above** the existing classical KMS — the KMS still wraps the data key with a classical KEK, and the hybrid construction sits on top. When KMS providers add PQ wrap, a follow-up runbook adds it.
- **Fully PQ-only deployments.** M2 ships hybrid only; PQ-only is an explicit future opt-in via a `pq_only` policy setting once the FIPS path is validated.

---

## 5. FIPS-track posture (informs M4)

**Current state (2026-05):** No FIPS 140-3 cryptographic module on the CMVP validated list covers ML-KEM-768. AWS-LC FIPS 3.0 is on the "modules in process" list since 2024-12-10 with no public ETA.

**Honest labelling:** A build with both `--features fips` and `--features pq` enabled will:

- Compile and behave identically to a `--features pq` build (RustCrypto `ml-kem` 0.3.0 backend).
- Emit `pq_fips_status: "pending_cmvp"` in `Debug` output of the produced envelope.
- **Not** claim FIPS validation for the hybrid path. README, dev-guide, CHANGELOG, and rustdoc all use the phrase "validation pending CMVP" — never "FIPS validated PQ."
- M4's CI lint will block any "FIPS validated PQ" string appearing in docs or changelog.

**Promotion criteria (future runbook):** When a CMVP cert covers ML-KEM-768 in a Rust-callable cryptographic module, a follow-up runbook:

1. Adds a new `pq-aws-lc` feature (or similar) that selects the validated implementation.
2. Documents the cert number, the validated module version, and the OS/platform constraints.
3. Updates this migration plan to reference the validated path.
4. Removes the "validation pending CMVP" label for the validated combination.

---

## 6. Migration steps for downstream consumers

This section is the consumer-facing playbook for adopting the M2 hybrid envelope.

### Step 1 — pin against the M1 wire format (today)

After M1 lands, downstream applications can:

```toml
secure_data = "0.1.2"  # or whatever the M1-shipping version is
```

Existing classical encrypt/decrypt continues unchanged. The `combiner_id` field is part of the envelope shape but classical envelopes do not emit it on the wire.

### Step 2 — adopt the `pq` feature (after M2)

```toml
secure_data = { version = "0.2", features = ["pq"] }
```

```rust
use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::encrypt_with_policy;

let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768);
let envelope = encrypt_with_policy(plaintext, "data-key", &provider, &policy).await?;
// envelope.algorithm == "X25519+ML-KEM-768/HKDF-SHA-256"
// envelope.combiner_id == Some(0x01)
```

Existing classical envelopes continue to decrypt unchanged. The hybrid path is opt-in per encrypt call.

### Step 3 — enforce minimum version (after M3)

```rust
let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768)
    .with_min_envelope_version(2);  // M3 API
```

Decrypt of a v1 envelope under this policy returns `DataError::AlgorithmRejectedByPolicy`.

### Step 4 — production rollout

1. Deploy a build with `--features pq` and the consumer-side decrypt for v1 + v2.
2. Wait until all producers are on the new build (zero v2 envelopes in circulation yet).
3. Switch producer policy to `prefer(HybridX25519MlKem768)`. New writes are v2.
4. Existing v1 envelopes decrypt unchanged; new writes are v2.
5. Once read traffic for v1 is below the application's tolerance threshold (typically a function of secrecy window), enforce `min_envelope_version=2` policy.

---

## 7. What this plan deliberately does not commit to

- A specific timeline for when `pq` becomes the default (not opt-in).
- A specific timeline for promoting the FIPS-track combination to validated status — depends on CMVP and the AWS-LC validation queue, both outside SunLit's control.
- ML-DSA / SLH-DSA signature support (separate runbook if needed).
- Replacing the symmetric AEAD with a PQ-AEAD (no PQ-AEAD exists; AES-256-GCM remains correct under credible PQ models).
- KMS-side hybrid wrap (depends on third-party KMS vendor support).

---

## 8. Refresh and supersession

This plan is **load-bearing** for M2 design decisions. Any future PR that materially changes a "Locked-in decision" (§2) must also update this plan and link the change in the CHANGELOG. The plan is not refreshed for every minor version bump — only for design changes.

A future plan revision is expected when:

- AWS-LC FIPS-validated ML-KEM lands (§5 promotion criteria).
- A CFRG QSF combiner reaches IETF consensus and gains a new combiner identifier in the table (§3.4).
- A Rust ecosystem audit produces a finding that materially affects the dependency choice (§2).

---

## 9. References

| Source | Purpose |
|---|---|
| [`docs/slo/research/pq-readiness-secure-data/dossier.md`](../research/pq-readiness-secure-data/dossier.md) | 29-source research dossier; locked-in decisions trace here |
| [`docs/slo/research/pq-readiness-secure-data/synthesis.md`](../research/pq-readiness-secure-data/synthesis.md) | Synthesis paragraphs — "the design must handle X because <source>." |
| [`docs/slo/idea/pq-readiness-secure-data.md`](../idea/pq-readiness-secure-data.md) | Idea doc — wedge, target user, success criteria |
| [`docs/slo/future/RUNBOOK-pq-readiness-secure-data.md`](../future/RUNBOOK-pq-readiness-secure-data.md) | v4 runbook — milestone plan + Contract Block per milestone |
| FIPS 203 (NIST, 2024) | ML-KEM specification |
| RFC 7748 | X25519 |
| RFC 5869 | HKDF |
| `draft-ietf-tls-hybrid-design` | Hybrid wire-format consensus pattern |
| [RustCrypto `ml-kem`](https://github.com/RustCrypto/formats/tree/master/ml-kem) v0.3.0 | Locked primary KEM implementation |
| [`aws-lc-rs`](https://github.com/aws/aws-lc-rs) | Future FIPS-track implementation |

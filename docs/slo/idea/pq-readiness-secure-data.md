# Idea — Post-Quantum Readiness in `secure_data`

**Slug:** `pq-readiness-secure-data`
**Created:** 2026-05-05
**Status:** Pre-research — feeds `/slo-research` then `/slo-plan`
**Source:** Identified during the awesome-rust-security-guide cross-walk (§18.3 Emerging Trends) as the only future-facing risk class the project does not yet address.

---

## Wedge

`secure_data` already has crypto-agility scaffolding (`AlgorithmPolicy` / `CryptoAlgorithm` enum, currently AES-256-GCM and XChaCha20-Poly1305) but no post-quantum (PQ) story. Critical-infrastructure consumers will eventually need a hybrid KEM (classical + ML-KEM) for envelope key wrap before "harvest now, decrypt later" attacks make stored ciphertexts retroactively recoverable. Without a reserved enum slot, a documented migration plan, and at least a feature-gated hybrid implementation behind a `pq` feature, the crate is one breaking change away from the migration when consumers ask for it.

## Target user

Two audiences: (1) the maintainer adding the capability today, and (2) downstream consumers operating systems with ≥10-year secrecy windows (utilities, healthcare, financial, defense) who must demonstrate to auditors that their cryptographic posture has a documented, executable PQ migration path — not just "we'll think about it."

## Why this is non-trivial

NIST finalized FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) in 2024–2025. The Rust ecosystem is mid-migration: `aws-lc-rs` ships ML-KEM, RustCrypto's `ml-kem` exists but maturity differs, and BoringSSL/OpenSSL each have their own readiness state. The "right" approach is a hybrid construction (X25519 + ML-KEM-768 for KEMs) per IETF `draft-ietf-tls-hybrid-design` thinking, but the wire-format choice (concatenation vs. KEM combiner) and the FIPS-readiness story for the hybrid (which validated module covers it) is moving. Picking the wrong primitive locks consumers into a non-validated path.

## What "done" looks like

A 3–4 milestone runbook that takes `secure_data` from "no PQ posture" to "documented hybrid KEM available behind a `pq` feature flag, with a written migration plan and a reserved `CryptoAlgorithm` slot." Not full FIPS validation — that is post-1.0. Concretely:

1. **M1** — Migration plan doc + `CryptoAlgorithm::HybridX25519MlKem768` enum slot + wire-format version field bump in `EncryptionEnvelope`.
2. **M2** — Hybrid KEM implementation behind `pq` feature flag (off by default), envelope encryption end-to-end.
3. **M3** — Backwards-compat decrypt for old envelopes; CVE/regression tests for downgrade attacks; algorithm-policy rejection rules.
4. **M4 (optional)** — FIPS-track readiness note: which PQ implementation has a path to FIPS 140-3 validation, and what the `fips` + `pq` feature combination means.

## Open questions for /slo-research

The codebase cannot answer these — they are "current state of PQ Rust crypto in 2026" / standards-tracking questions:

1. **Which Rust crate is the production-ready ML-KEM implementation as of Q2 2026?** Candidates: `aws-lc-rs` (FIPS-track), RustCrypto `ml-kem`, `liboqs-rust`, BoringSSL bindings. Drives M2's primary dependency choice. Look for: maintenance cadence, audit history, known-answer test (KAT) coverage, FIPS 140-3 validation status, ecosystem adoption (rustls, OpenSSH, hybrid-PQ work in major projects).

2. **Hybrid construction wire format — IETF draft consensus.** Is concatenation (`X25519_shared_secret || ML-KEM_shared_secret`) still the consensus, or has a KEM combiner (HKDF-based) won? Drives M1's wire-format design. Look for: latest revision of `draft-ietf-tls-hybrid-design`, CFRG hybrid-PKE drafts, IETF 119/120/121 minutes, BoringSSL/OpenSSL hybrid implementations.

3. **FIPS 140-3 status for hybrid KEMs** — does any validated cryptographic module (Vendor X, version Y, certificate Z) currently cover `X25519 + ML-KEM-768`? If not, what is the validation timeline? Drives M4 scope. Look for: NIST CMVP search for ML-KEM, AWS-LC FIPS module Bulletin status, openssl-fips ML-KEM landing.

4. **"Harvest now, decrypt later" attack-model concreteness** — what is the current credible-threat timeline for ML-KEM and ML-DSA against a state-level adversary? Specifically: is the 10-year secrecy assumption that drives PQ adoption based on published cryptanalysis, NIST PQC competition assumptions, or industry consensus? Drives the migration-plan doc's threat-model framing. Look for: Mosca's theorem updates, ETSI quantum-safe cryptography reports, NSA CNSA 2.0 timeline, real-world quantum-computer scaling milestones in 2025–2026.

5. **What does the Rust ecosystem leader (rustls / aws-lc-rs / RustCrypto) recommend for a service-side library that must work alongside an existing classical KMS (AWS KMS, Vault Transit)?** Specifically: do AWS KMS / HashiCorp Vault Transit yet support PQ or hybrid wrapping, or does the application layer need to do hybrid wrapping above the KMS-managed classical key? Drives M2's integration with the existing `KeyProvider` trait. Look for: AWS KMS hybrid-key blog posts, Vault Transit roadmap, GCP Cloud KMS PQ status.

## Out of scope for research

- Lattice-cryptanalysis primary-research review.
- Patent landscape — assumed clear for ML-KEM/ML-DSA/SLH-DSA per NIST competition outcomes.
- ML-DSA / SLH-DSA signature use (this work is KEM-only; signature-side PQ is a separate runbook if needed).
- Replacing existing AEAD (AES-256-GCM remains correct PQ-side; PQ affects the *key exchange* / *key wrap*, not symmetric AEAD).

## Constraints

- Solo maintainer.
- Cannot break existing AES-256-GCM / XChaCha20-Poly1305 envelopes — old data must still decrypt.
- `pq` feature must be off by default; non-PQ consumers must compile and behave identically.
- Must integrate with the existing `KeyProvider` trait without forcing every provider to implement PQ today.
- FIPS-track is desirable but not required for M1–M3.

## Success criteria

After research, `/slo-plan` can produce a runbook where (a) every primitive choice cites a sourced rationale, (b) the wire-format design is forward-compatible (no second breaking migration in 12 months), and (c) the threat-model framing in the migration-plan doc is defensible to a regulated-industry auditor.

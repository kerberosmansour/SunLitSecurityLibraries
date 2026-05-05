---
name: pq-readiness-secure-data
researched: 2026-05-05
incomplete: true
---

# Research Dossier — Post-Quantum Readiness in `secure_data`

## Market / Adopters

Hybrid post-quantum KEM is mid-deployment in production cloud and TLS infrastructure, but envelope-level (above-KMS) PQ wrapping is not yet a shipping feature in any major KMS.

- **AWS** launched ML-KEM-based hybrid post-quantum TLS for AWS KMS, ACM, and Secrets Manager on 2025-04-07 (X25519MLKEM768 in non-FIPS endpoints), and announced the deprecation of CRYSTALS-Kyber across all AWS endpoints in 2026 in favour of ML-KEM. AWS-LC FIPS 3.0 was added to the NIST CMVP "modules in process" list on 2024-12-10 as the first cryptographic module to seek FIPS 140-3 validation for ML-KEM (all three parameter sets) [1][2].
- **Cloudflare** reported well over 60% of human-generated TLS traffic protected with hybrid ML-KEM as of October 2025; 6M+ customer domains were upgraded by default to PQ-capable TLS [3].
- **Google Cloud KMS** released ML-KEM-768 and ML-KEM-1024 KEM operations in preview, and explicitly recommends X-Wing (X25519 + ML-KEM-768) for general-purpose hybrid; full PQC for GCP infrastructure connections targeted for 2026 [4].
- **Signal** shipped PQXDH (X25519 + CRYSTALS-Kyber-1024) to production in 2023–2024 and has since added the SPQR ratchet, demonstrating end-to-end hybrid PQ in a production messenger [5].
- **HashiCorp Vault Transit** has experimental PQC signature support (ML-DSA, SLH-DSA) but ML-KEM and hybrid wrapping in Transit remain on the roadmap and explicitly "should not be used in production" as of early 2026 [6].
- **rustls** moved hybrid X25519MLKEM768 (and SecP256r1MLKEM768, SecP384r1MLKEM1024) into the main crate as of 0.23.22, gated behind a `prefer-post-quantum` feature [7].

## Direct equivalents (Rust crates that implement ML-KEM today)

| Crate / library | Maturity (audit, FIPS) | KEM primitive | Concrete differentiator | URL |
|---|---|---|---|---|
| `aws-lc-rs` (with `aws-lc-fips-sys` backing AWS-LC-FIPS 3.0) | Production-ready; ring-API-compatible. AWS-LC-FIPS 3.0 is on the CMVP "modules in process" list (2024-12-10); no ML-KEM 140-3 cert issued yet. | ML-KEM-512 / 768 / 1024 (FIPS 203) | Only Rust crate with a credible near-term FIPS 140-3 path for ML-KEM; ships an unsafe-FFI binding to a battle-tested C library used in AWS production. | [8][2] |
| `ml-kem` (RustCrypto) | v0.3.0 pure-Rust; tested against NIST KATs; **never independently audited**; README says "USE AT YOUR OWN RISK!" | ML-KEM-512 / 768 / 1024 (FIPS 203 final) | Pure Rust, no C deps, MIT/Apache-2.0; easiest to integrate into a no-FFI workspace; viable for non-FIPS hybrid construction in `secure_data`'s `pq` feature. | [9][10] |
| `libcrux-ml-kem` (Cryspen) | Pre-1.0 (`<0.1`); portions formally verified for panic-freedom, correctness, and secret-independence in F* via the hax toolchain; no independent audit; maintainers explicitly say "talk to us before production". | ML-KEM-512 / 768 / 1024 with portable + AVX2 paths | Only Rust ML-KEM with formal verification of significant portions of the implementation; strongest correctness story but pre-release versioning. | [11][12] |
| `liboqs-rust` (`oqs` / `oqs-sys`) | Active (last update 2026-03-12); upstream liboqs 0.15.0 released 2025-11-14. Project Eleven survey marks it "not recommended" for production due to lack of audit and prototyping framing. | ML-KEM via liboqs C library | Broadest algorithm catalogue (also Falcon, HQC, Classic McEliece) for experimentation; positioned by upstream as "for prototyping". | [13][12] |
| `fips203` (integritychain) | Pure Rust, embedded-friendly; not audited. | ML-KEM-512 / 768 / 1024 (FIPS 203) | `no_std` story for embedded targets; smaller maintainer, less ecosystem traction than RustCrypto `ml-kem`. | [14] |

## Adjacent / supporting projects

| Project | Why relevant (KMS PQ support, hybrid-KEM RFC, validation track) | URL |
|---|---|---|
| `rustls-post-quantum` / rustls 0.23.22+ | Reference Rust integration of X25519MLKEM768 hybrid; shows the consensus wire format and parameter choice. | [7] |
| AWS KMS hybrid PQ TLS | Production hybrid-PQ at the KMS transport layer (X25519MLKEM768) — but data-key wrapping inside KMS is still classical. Confirms the gap `secure_data` is filling above-KMS. | [1] |
| Google Cloud KMS Quantum-safe KEMs (preview) | First major cloud KMS to expose ML-KEM-768/1024 KEM operations as a service primitive; recommends X-Wing for clients. | [4] |
| HashiCorp Vault PQC roadmap | Confirms ML-DSA/SLH-DSA experimental and ML-KEM still pending; downstream consumers will need application-layer hybrid wrapping until Vault Transit ships. | [6] |
| Open Quantum Safe (`liboqs`) | Reference implementation used to cross-check KATs and as a fallback algorithm source. | [13] |
| Cryspen `libcrux` formal verification | Demonstrates F*/hax verification of ML-KEM is possible in Rust; informs whether to defer FIPS in favour of formal-verified path. | [11] |

## Technical prior art / standards

- **FIPS 203 (ML-KEM)** — NIST final standard published 2024-08-13; specifies ML-KEM-512/768/1024 parameter sets derived from CRYSTALS-Kyber [15].
- **FIPS 140-3** — Module-validation framework. As of 2026-05, no cryptographic module has a published FIPS 140-3 certificate covering ML-KEM; AWS-LC FIPS 3.0 is the lead candidate, on CMVP "modules in process" list since 2024-12-10 [16][2].
- **`draft-ietf-tls-hybrid-design-16`** — Last revision dated 2025-09-07. Specifies the **concatenation** wire format: `ML-KEM ciphertext || X25519 share`, with the two shared secrets concatenated into the TLS 1.3 key schedule (no HKDF-style combiner). Concatenation is justified by NIST SP 800-56C "approved" status when one input is approved [17].
- **`draft-irtf-cfrg-hybrid-kems-10`** (CFRG) — Generic hybrid PQ/T KEM constructions. Defines QSF combiner family; notes simple concatenation suffices when followed by a KDF, but stronger IND-CCA2-preserving combiners are needed if either input may be adversarially chosen [18].
- **`draft-connolly-cfrg-xwing-kem-10`** — Latest revision 2026-03-02. X-Wing = X25519 + ML-KEM-768 with SHA3-256 combiner; produces a fixed 32-byte shared secret. **Individual submission**, *not* an adopted CFRG WG item; explicitly "no formal standing in the IETF standards process" [19].
- **`draft-ietf-tls-ecdhe-mlkem-04`** — TLS-specific X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 codepoints [20].
- **`draft-ietf-pquip-pqc-engineers-14`** — Engineering guidance for PQC migration (informational) [21].
- **NSA CNSA 2.0** — Mandates ML-KEM and ML-DSA for National Security Systems. Networking equipment must support and prefer CNSA 2.0 by 2026; new acquisitions must be CNSA 2.0 compliant from 2027-01-01; full transition by 2035 [22].
- **ETSI / Global Risk Institute Quantum Threat Timeline 2026** — Mosca/Piani report (2026-03-09) puts the 10-year probability of a cryptographically relevant quantum computer at 28–49% (highest in the report's 7-year history) [23].
- **ENISA Post-Quantum Cryptography report** — Provides EU-side framing for migration urgency [24].

## Regulatory / legal

- **FIPS 140-3 status for ML-KEM modules** — No issued certificates as of 2026-05. AWS-LC FIPS 3.0 is the only mainstream module on the CMVP modules-in-process list with ML-KEM. RustCrypto, libcrux, and liboqs have *no* FIPS validation track. Implication: a `fips`-feature build of `secure_data` cannot offer a validated ML-KEM today regardless of crate choice [16][2].
- **Export-control posture (Wassenaar / EAR)** — None apply because ML-KEM/ML-DSA/SLH-DSA are publicly published NIST standards using publicly available source code; this places them under EAR's TSU exception for "publicly available" cryptographic source code. Per NIST competition outcomes, no patent encumbrance is asserted for the standardized variants. (No regulatory carve-out specific to ML-KEM has been published; classification follows generic open-source crypto rules.)
- **EU Cyber Resilience Act / NIS2 PQ language** — The 2026-01-20 European Commission cybersecurity package proposed amendments to the Cybersecurity Act and NIS2 require Member States to adopt PQC migration policies in their national cybersecurity strategies, with critical-infrastructure transition mandated by end-of-2030 and general transition starting end-of-2026 [25][26].
- **NSA CNSA 2.0** — ML-KEM is the *only* approved KEM for NSS; no hybrid is mandated, but hybrids are not prohibited during transition. Pure ML-KEM-1024 is the long-term CNSA 2.0 target for highest-security NSS data; CNSA 2.0 does not endorse X-Wing or X25519-hybrid as the long-term steady state [22].

## Open questions that research did not answer

- **Is X-Wing on a path to CFRG WG adoption, or will the field consolidate on `draft-irtf-cfrg-hybrid-kems` generic combiners?** X-Wing is at -10 (2026-03-02) but still individual-submission. Risk: if `secure_data` ships X-Wing wire format and CFRG adopts a different combiner spec, M1's wire format becomes legacy.
- **Concrete FIPS 140-3 certificate number and validation date for AWS-LC FIPS 3.0 with ML-KEM.** The CMVP "modules in process" listing does not provide an ETA. Sourcing this would let the planner quote a certificate ID in the M4 readiness note.
- **Whether HashiCorp Vault Transit's eventual ML-KEM support will offer hybrid envelope wrapping that obsoletes application-layer hybrid wrapping, and on what date.** Public roadmap is silent beyond "research and build support for hybrid schemes".
- **Does AWS KMS expose ML-KEM at the data-key-wrap layer (not just TLS)?** Public docs only describe transport-level hybrid TLS; whether `GenerateDataKeyPair`-style ML-KEM keys are on the roadmap is unstated.
- **Independent audit status of any Rust ML-KEM crate.** No public audit report exists for `aws-lc-rs`, `ml-kem`, or `libcrux-ml-kem` ML-KEM code paths as of 2026-05. Marking `incomplete: true` for this reason; downstream consumers in regulated industries will ask.

# Sources — pq-readiness-secure-data

All URLs accessed 2026-05-05.

[1] AWS Security Blog, "ML-KEM post-quantum TLS now supported in AWS KMS, ACM, and Secrets Manager" — https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/ — Confirms AWS KMS launched X25519MLKEM768 hybrid TLS on 2025-04-07; CRYSTALS-Kyber removed in 2026.

[2] AWS Security Blog, "AWS-LC FIPS 3.0: First cryptographic library to include ML-KEM in FIPS 140-3 validation" — https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/ — AWS-LC FIPS 3.0 placed on CMVP modules-in-process list 2024-12-10 with all three ML-KEM parameter sets.

[3] Cloudflare Blog, "State of the post-quantum Internet in 2025" — https://blog.cloudflare.com/pq-2025/ — Reports >60% of human-generated TLS traffic to Cloudflare protected with hybrid ML-KEM by Oct 2025.

[4] Google Cloud Blog, "Announcing quantum-safe Key Encapsulation Mechanisms in Cloud KMS" — https://cloud.google.com/blog/products/identity-security/announcing-quantum-safe-key-encapsulation-mechanisms-in-cloud-kms — GCP Cloud KMS preview of ML-KEM-768/1024; recommends X-Wing for general-purpose hybrid.

[5] Signal Blog, "Quantum Resistance and the Signal Protocol" — https://signal.org/blog/pqxdh/ — Signal PQXDH specification (X25519 + Kyber-1024) shipped to production.

[6] HashiCorp Blog, "NIST's post-quantum cryptography standards: Our plans" — https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans — Vault Transit ML-DSA/SLH-DSA experimental; ML-KEM and hybrids on roadmap, not production-ready.

[7] rustls-post-quantum docs / rustls 0.23.22 release notes — https://docs.rs/rustls-post-quantum/latest/rustls_post_quantum/ — ML-KEM hybrid moved into rustls core behind `prefer-post-quantum`.

[8] aws-lc-rs README and crates.io page — https://github.com/aws/aws-lc-rs — v1.16.3 (2026-04-15), Apache-2.0/ISC dual; ring-API-compatible.

[9] RustCrypto `ml-kem` crate documentation — https://docs.rs/ml-kem/latest/ml_kem/ — v0.3.0; FIPS 203 (final); "USE AT YOUR OWN RISK", never independently audited.

[10] crates.io listing for `ml-kem` — https://crates.io/crates/ml-kem — Pure-Rust ML-KEM, MIT/Apache-2.0.

[11] Cryspen, "Verifying Libcrux's ML-KEM" — https://cryspen.com/post/ml-kem-verification/ — F*/hax verification of panic-freedom, correctness, secret-independence.

[12] Project Eleven Blog, "The State of Post-Quantum Cryptography in Rust: The Belt is Vacant" — https://blog.projecteleven.com/posts/the-state-of-post-quantum-cryptography-in-rust-the-belt-is-vacant — Comparative survey rating aws-lc-rs and libcrux as production-ready; rustcrypto experimental; liboqs/pqcrypto not recommended.

[13] Open Quantum Safe, `liboqs-rust` GitHub — https://github.com/open-quantum-safe/liboqs-rust — Active prototyping bindings; upstream liboqs 0.15.0 released 2025-11-14.

[14] integritychain `fips203` GitHub — https://github.com/integritychain/fips203 — Pure-Rust ML-KEM-512/768/1024 with `no_std` support.

[15] NIST FIPS 203 final — https://csrc.nist.gov/pubs/fips/203/final — ML-KEM standard published 2024-08-13.

[16] NIST CMVP "Modules in Process" list — https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list — Source of truth for which modules have ML-KEM in 140-3 validation.

[17] IETF `draft-ietf-tls-hybrid-design` — https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/ — Revision 16, 2025-09-07; concatenation-based wire format for hybrid TLS 1.3 key exchange.

[18] CFRG `draft-irtf-cfrg-hybrid-kems` — https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/ — Revision 10 (2026); QSF combiner constructions for hybrid PQ/T KEMs.

[19] CFRG `draft-connolly-cfrg-xwing-kem` — https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ — Revision 10, 2026-03-02; individual submission, not WG-adopted.

[20] IETF `draft-ietf-tls-ecdhe-mlkem` — https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/ — Revision 04; X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 TLS codepoints.

[21] IETF `draft-ietf-pquip-pqc-engineers` — https://datatracker.ietf.org/doc/draft-ietf-pquip-pqc-engineers/ — Revision 14; engineering guidance for PQC migration.

[22] NSA, "Commercial National Security Algorithm Suite 2.0 Algorithms" CSA — https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF — Mandates ML-KEM/ML-DSA; 2026 networking-equipment milestone; 2027 NSS acquisition mandate; 2035 full transition.

[23] Global Risk Institute, "Quantum Threat Timeline Report 2026" (Mosca, Piani) — https://globalriskinstitute.org/publication/quantum-threat-timeline/ — 28–49% expert probability of CRQC within 10 years (2026 edition, 9 March 2026).

[24] ENISA, "Post-Quantum Cryptography: Current state and quantum mitigation" — https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation — EU-side migration framing.

[25] European Commission, "EU reinforces its cybersecurity with post-quantum cryptography" — https://digital-strategy.ec.europa.eu/en/news/eu-reinforces-its-cybersecurity-post-quantum-cryptography — Coordinated PQC transition roadmap; Member States start 2026, critical infrastructure by 2030.

[26] Mayer Brown, "European Commission Proposes Major Cybersecurity Package to Strengthen EU Cyber Resilience" — https://www.mayerbrown.com/en/insights/publications/2026/02/european-commission-proposes-major-cybersecurity-package-to-strengthen-eu-cyber-resilience — 2026-01-20 cybersecurity package detail; PQC migration policies required in national strategies.

[27] AWS CSRC presentation, "Deploying FIPS 203: ML-KEM at AWS" — https://csrc.nist.gov/csrc/media/Presentations/2025/building-post-quantum-cloud-services/images-media/buillding-pw-cloud-services.pdf — AWS deployment specifics for ML-KEM in FIPS-track services.

[28] Memory Safety / Prossimo, "The Rustls TLS Library Adds Post-Quantum Key Exchange Support" — https://www.memorysafety.org/blog/pq-key-exchange/ — Background on rustls integrating ML-KEM hybrid.

[29] AWS KMS docs, "Using hybrid post-quantum TLS with AWS KMS" — https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html — Confirms ML-KEM hybrid is at TLS layer only; data-key wrapping inside KMS is not described as PQ.

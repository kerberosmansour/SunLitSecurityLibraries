# Sources — Formal Verification (Kani + TLA+)

All access dates: 2026-05-05.

## Kani — capability, limitations, releases

1. [Kani Rust Verifier — Rust feature support](https://model-checking.github.io/kani/rust-feature-support.html) — Authoritative table of supported Rust language features (Yes/Partial/No), notably `async/await: No`, `inline asm: No`, FFI cannot be verified.
2. [Kani Rust Verifier — Limitations](https://model-checking.github.io/kani/limitations.html) — Top-level overview pointing to undefined-behaviour, feature-support, overrides pages.
3. [Kani Rust Verifier — Getting started](https://model-checking.github.io/kani/) — Cadence: monthly release, syncs with a recent Rust nightly.
4. [Kani Rust Verifier — Releases (GitHub)](https://github.com/model-checking/kani/releases) — Most recent shown is 0.67.0 (Jan 2025) with array-handling fixes; 0.66.0 added loop-contract support; 0.65.0 added bitwuzla/cvc5/z3 multi-solver and `--prove-safety-only`.
5. [Kani Rust Verifier — Verification results](https://model-checking.github.io/kani/verification-results.html) — Possible outcomes (proved, counterexample, out-of-resources).
6. [Kani Rust Verifier — Intrinsics](https://model-checking.github.io/kani/rust-feature-support/intrinsics.html) — Intrinsics support matrix (relevant for SIMD / crypto-crate primitives).
7. [Kani GitHub Action repository](https://github.com/model-checking/kani-github-action) — The official `model-checking/kani-github-action` action; documents `command`, `args`, `kani-version` inputs.
8. [Kani CI Action — install-github-ci docs](https://model-checking.github.io/kani/install-github-ci.html) — Mentions if Kani is too slow for per-PR, run on a schedule; GitHub jobs terminate at 6 hours.
9. [Easily verify your Rust in CI with Kani and GitHub Actions](https://model-checking.github.io//kani-verifier-blog/2022/12/21/easily-verify-your-rust-in-ci-with-kani.html) — Kani team's recommended CI pattern. Flagged: 2022, may be stale on action specifics.
10. [Verify the Safety of the Rust Standard Library — AWS Open Source Blog](https://aws.amazon.com/blogs/opensource/verify-the-safety-of-the-rust-standard-library/) — Rust Foundation challenge funding $5K–$25K per challenge; Kani is one of the approved tools.
11. [Lessons Learned from Verifying the Rust Standard Library (arXiv 2510.01072)](https://arxiv.org/html/2510.01072v2) — As of writing, 361 of 9078 unsafe `core` functions annotated with Kani contracts (~3.98% coverage). Confirms Kani is the most-used tool of the four accepted (Flux/ESBMC/Kani/VeriFast).

## Kani adopters

12. [s2n-quic — Kani dev guide](https://aws.github.io/s2n-quic/dev-guide/kani.html) — s2n-quic uses Kani via Bolero. >30 Bolero+Kani harnesses.
13. [How s2n-quic uses Kani to inspire confidence — Kani Verifier Blog](https://model-checking.github.io//kani-verifier-blog/2023/05/30/how-s2n-quic-uses-kani-to-inspire-confidence.html) — Concrete proof runtimes: ~45s for RTT-estimator harness, ~3s for packet-number decode. Uses the Kani GitHub Action; runs on PR and merge to main.
14. [How Open Source Projects are Using Kani to Write Better Software in Rust — AWS Open Source Blog](https://aws.amazon.com/blogs/opensource/how-open-source-projects-are-using-kani-to-write-better-software-in-rust/) — Adopters: Firecracker, Hifitime, s2n-quic. Lists bug counts (Firecracker rate-limiter +5, VirtIO +1; Hifitime ≥8 categories).
15. [Using Kani to Validate Security Boundaries in AWS Firecracker — Kani Verifier Blog (2023-08)](https://model-checking.github.io//kani-verifier-blog/2023/08/31/using-kani-to-validate-security-boundaries-in-aws-firecracker.html) — Firecracker rate-limiter and VirtIO queue-overlap proofs. Flagged: 2023, but project still active.
16. [Using the Kani Rust Verifier on Tokio Bytes — Kani Verifier Blog](https://model-checking.github.io/kani-verifier-blog/2022/08/17/using-the-kani-rust-verifier-on-tokio-bytes.html) — `BytesMut::with_capacity` + `split_off` proofs using ghost-state representation invariant. Flagged: 2022, blog-era; pattern is reusable but the harness file may have moved.
17. [tokio-rs/prost — KANI.md](https://github.com/tokio-rs/prost/blob/master/KANI.md) — Prost (protobuf) ships in-tree Kani docs and recommends the GitHub Action over local bin "because of instability in Kani internals".
18. [Formal Verification of Cryptographic Software at AWS — NIST 2024 talk](https://www.nist.gov/document/formal-verification-cryptographic-software-aws-current-practices-and-future-trends) — AWS's hybrid stack: Kani for s2n-quic, Coq+Cryptol for aws-lc, s2n-bignum machine-checked proofs. Confirms Kani is production-grade for non-crypto Rust.
19. [Expanding the Rust Formal Verification Ecosystem: ESBMC — Rust Foundation](https://rustfoundation.org/media/expanding-the-rust-formal-verification-ecosystem-welcoming-esbmc/) — Confirms Foundation backing for the Rust verification ecosystem and lists Flux/ESBMC/Kani/VeriFast as approved tools.

## TLA+ — tools and adoption

20. [TLA+ Tools releases (GitHub)](https://github.com/tlaplus/tlaplus/releases) — Latest is v1.8.0 "The Clarke release" (May 2024); TLA+ Toolbox is no longer actively maintained — VS Code extension / CLI is the recommended path. Flagged: tooling release cadence has slowed.
21. [Apalache releases (GitHub)](https://github.com/apalache-mc/apalache/releases) — Latest v0.57.0 (April 24, 2026); active monthly cadence (v0.56.0/0.56.1/0.57.0 across Mar-Apr 2026). JSON-RPC server, Quint integration ongoing.
22. [Apalache project home — apalache-mc.org](https://apalache-mc.org/) — Self-described as the SMT-backed symbolic model checker for TLA+ and Quint.
23. [Apalache GitHub issues — funding/maintenance signal](https://github.com/apalache-mc/apalache/issues) — Confirmed: not currently funded by any single org; maintained by Konnov / Kukovec / Pani after Informal Systems' grant ended in 2024. Flag: bus factor risk.
24. [Apalache paper: TLA+ Model Checking Made Symbolic (OOPSLA 2019)](https://dl.acm.org/doi/10.1145/3360549) — Foundational paper: Apalache encodes TLA+ to SMT (Z3) for state-explosion-resistant verification. Flagged: 2019, but architecture is unchanged.
25. [Current Versions of the TLA+ Tools — Lamport, October 2024](https://lamport.azurewebsites.net/tla/current-tools.pdf) — Lamport's authoritative pointer to current tooling. Flagged: 2024, still the most recent version-of-record.
26. [TLA+ Examples repository (master/specifications)](https://github.com/tlaplus/Examples/tree/master/specifications) — 90+ specs. None directly model circuit-breaker, session, or step-up. Closest: leader-election (Chang-Roberts, Yo-Yo), termination-detection (EWD840/EWD998), mutual-exclusion (Boulangerie, Peterson). Confirms novel-spec authoring is required for SunLit's M4/M5.
27. [How Amazon Web Services Uses Formal Methods — CACM](https://cacm.acm.org/research/how-amazon-web-services-uses-formal-methods/) — Foundational case study; AWS has used TLA+ on S3, DynamoDB, EBS since 2011.
28. [Leader Election in Distributed Systems — AWS Builders' Library](https://aws.amazon.com/builders-library/leader-election-in-distributed-systems/) — Recommends TLA+ for distributed-algorithm correctness; abstracts leases.
29. [nearai/ironclaw issue #1225 — Write TLA+ specs for circuit breaker, agentic loop, failover](https://github.com/nearai/ironclaw/issues/1225) — A 2026 in-progress proposal modeling Closed/Open/HalfOpen, with named invariants ("no Closed→HalfOpen direct transition", "Open eventually reaches HalfOpen", "success counter resets on HalfOpen entry"). Spec not yet published but the invariant list is reusable as a starting abstraction. Flagged: aspirational, not a published spec yet.
30. [Formal Analysis of Web SSO using Tamarin (Hofmeier ETHZ thesis)](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/information-security-group-dam/research/software/ba-19-hofmeier-oidc.pdf) — Existing precedent for OIDC formal verification — uses Tamarin (symbolic protocol prover), not TLA+. Confirms TLA+ is not the standard for OAuth/OIDC verification; SunLit's session-step-up spec models the *state machine*, not the protocol.

## CI norms

31. [s2n-quic CI dev-guide](https://github.com/aws/s2n-quic/blob/main/docs/dev-guide/ci.md) — Confirms Kani runs as part of the regular CI test suite (PR + merge-to-main).
32. [Use Kani action in CI — s2n-quic PR #1556](https://github.com/aws/s2n-quic/pull/1556) — The actual PR that wired the Kani GitHub Action into s2n-quic's CI; source-of-truth for "how a real adopter wires it up".
33. [Use GitHub Actions Timeouts to Protect Your Budget — emmer.dev](https://emmer.dev/blog/use-github-actions-timeouts-to-protect-your-budget/) — General guidance: set `timeout-minutes` on every job. GitHub default cap is 6 hours.

## Standards / regulatory

34. [DO-178C — Wikipedia](https://en.wikipedia.org/wiki/DO-178C) — DO-178C explicitly admits formal methods (theorem proving, model checking, abstract interpretation) as alternatives to dynamic testing via DO-333.
35. [DO-178C — Wind River overview](https://www.windriver.com/solutions/learning/do-178c) — Industry summary; confirms DO-333 supplement.
36. [DO-178C — Relation to Safety Standards (AbsInt)](https://www.absint.com/qualification/do-178c.htm) — Maps DO-178C to IEC 61508 / ISO 26262 / IEC 62304 lineage.
37. [EU Cyber Resilience Act — implementation timeline](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) — CRA in force 10-Dec-2024; main obligations apply 11-Dec-2027. Reporting obligations 11-Sep-2026.
38. [ENISA / JRC CRA Requirements Standards Mapping](https://www.enisa.europa.eu/publications/cyber-resilience-act-requirements-standards-mapping) — Confirms current ENISA/JRC mapping does not name "formal verification" as a required technique.
39. [NIST SP 800-53 Rev 5 — SA-11 Developer Testing and Evaluation (CSF Tools)](https://csf.tools/reference/nist-sp-800-53/r5/sa/sa-11/) — SA-11 enhancements: static, dynamic, manual review, threat modeling. Formal verification is not named directly but "additional types of testing/evaluation" is open-ended.
40. [NIST SP 800-53 Rev 5 — full PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) — Authoritative control catalog.

---
name: formal-verification-kani-tla
researched: 2026-05-05
incomplete: false
---

# Research Dossier — Formal Verification for SunLit (Kani + TLA+)

## Kani — current capability for production Rust crates

Kani is a bit-precise SAT/SMT-backed model checker for Rust, maintained by AWS via the model-checking org, with a monthly release cadence pinned to a recent Rust nightly. The most recent release shown in GitHub Releases is **0.67.0 (Jan 2025)**; 0.66.0 added loop contracts for `while let`/`for`, and 0.65.0 added multi-solver support (bitwuzla/cvc5/z3) plus `--prove-safety-only` [src 4]. Proofs are written as `#[kani::proof]` harnesses using `kani::any()` for symbolic inputs [src 1, 7]. Stable Rust coverage is broad: most of `core`/`alloc`, common iterator chains, `Arc`, references, slices, `Vec`/`String`/`Option`/`Result` are usable. The verify-rust-std challenge has Kani contracts on 361 of 9078 unsafe `core` functions (~3.98%), demonstrating non-trivial real-world stdlib coverage [src 11]. AWS-backed, Rust Foundation-recognised, active monthly cadence — green for production reliance.

## Real-world Kani adopters (Rust security / network crates)

| Project | What they verify with Kani | CI integration shape | URL |
|---|---|---|---|
| AWS s2n-quic (QUIC) | >30 Bolero+Kani harnesses: RTT estimator, packet-number decode, varint parsing, transport-parameter bounds | `model-checking/kani-github-action` on every PR + merge-to-main; ~3–45s per harness | [src 12, 13, 32] |
| AWS Firecracker (microVM) | Rate-limiter rounding/overflow, VirtIO queue not overlapping MMIO, security boundaries | Project-internal; proofs found 5 rate-limiter bugs + 1 VirtIO crash bug | [src 14, 15] |
| Tokio Bytes (`BytesMut`) | `with_capacity` + `split_off` preserve representation invariant via ghost state | Demonstration / blog-grade; pattern reusable | [src 16] |
| tokio-rs/prost (protobuf) | In-tree `KANI.md`; recommends GitHub Action over local install for CI stability | Documented integration pattern; advisory | [src 17] |
| Hifitime (time math) | Boundary correctness on duration arithmetic (eq, neg, add, sub) | Single PR found ≥8 bug categories | [src 14] |

## Kani — known limitations relevant to SunLit

- **Async / concurrency: NO.** "Concurrent features are currently out of scope"; Kani warns and compiles concurrent code as if sequential [src 1, 2]. **SunLit impact:** half-open probe in `secure_resilience` and async middleware in `secure_boundary` cannot be Kani-proved — those properties belong in TLA+.
- **FFI: NO** (cannot verify code called through FFI; C-FFI milestone open but unshipped) [src 1]. **SunLit impact:** Kani cannot reach into `aes-gcm`/`chacha20poly1305` if backends dispatch to `aes-ni` or C; proofs on `secure_data` must target the Rust wrapper (nonce assembly, AAD framing) and treat the AEAD primitive as an opaque axiom.
- **Inline assembly (`asm!`/`asm_global!`): NO** [src 1]. Same mitigation as FFI.
- **SIMD intrinsics: partial** [src 6]. Same mitigation.
- **Traits / dyn: partial** ("semantics around some advanced features are not formally defined") [src 4]. **SunLit impact:** keep `secure_authz` policy traits monomorphic in proof harnesses behind `#[cfg(kani)]` wrappers.
- **Stack unwinding / panics: partial.** Default `panic=unwind` not modelled; harnesses commonly run `panic=abort`.
- **Macros / serde derive:** post-expansion code is verifiable in principle, but state-explosion on large derive expansions is a real risk. **SunLit impact:** `secure_boundary` proof harnesses must enter at hand-written narrow functions, not the full axum middleware stack.

## TLA+ / TLC / Apalache — current state for protocol-level verification

**TLC** (explicit-state checker shipped with TLA+ Tools) is at v1.8.0 "Clarke" (May 2024); the TLA+ Toolbox UI is officially unmaintained — VS Code extension or CLI is the recommended path [src 20, 25]. JDK 11+ in CI is sufficient. **Apalache** (SMT-backed symbolic checker) is at v0.57.0 (April 24, 2026) with monthly releases through 2026 [src 21]. Funding is the one yellow flag: as of 2024 Informal Systems' grant ended; Apalache is now maintained by Konnov / Kukovec / Pani as volunteers — bus-factor risk worth documenting [src 23]. CI cost is low for both: TLC is `java -jar tla2tools.jar -workers auto Spec` from a checkout step; Apalache provides Docker images.

## Existing TLA+ specs we can borrow from (circuit breaker, session/step-up auth)

| Spec / project | Pattern modeled | URL | Suitability for SunLit |
|---|---|---|---|
| nearai/ironclaw issue #1225 (in-progress 2026) | Closed/Open/HalfOpen breaker with consecutive-failures, half-open-successes, abstract clock; named invariants ("no direct Closed→HalfOpen", "Open eventually reaches HalfOpen", "success counter resets on HalfOpen entry") | [src 29] | High — invariant list is directly reusable as the M4 abstraction skeleton. Caveat: spec text not yet published. |
| TLA+ Examples — Chang-Roberts / Yo-Yo (leader election) | Leader election in a ring | [src 26] | Low for the problem, but shows abstract-clock-as-tick-sequence pattern needed for M4. |
| TLA+ Examples — EWD840 / EWD998 (termination detection) | Distributed termination detection | [src 26] | Medium — "eventually X" liveness pattern reusable for "Open eventually reaches HalfOpen". |
| TLA+ Examples — Boulangerie / Peterson Lock | Mutex / one-writer invariants | [src 26] | Medium — abstraction for half-open *single-probe* rule (structurally a one-token mutex over a window). |
| Hofmeier ETHZ thesis (Tamarin OIDC SSO) | OAuth/OIDC SSO formal model | [src 30] | Low — Tamarin/ProVerif are standard for OAuth/OIDC, not TLA+. SunLit's `secure_identity` spec models the *local* session state machine and treats the OIDC handshake as an opaque transition. |
| AWS Builders' Library — Leader Election | TLA+ used internally for leader/lease at AWS | [src 27, 28] | High inspirational value — confirms TLA+ is the right tool for state-machine-with-leases. |

The TLA+ Examples repo (90+ specs) does **not** contain a published circuit-breaker or session/step-up spec [src 26]. SunLit will be authoring both from scratch; the ironclaw invariant list is the closest prior art.

## CI integration norms

| Project | Tool | Advisory or blocking? | Runtime cap | URL |
|---|---|---|---|---|
| AWS s2n-quic | Kani via official GitHub Action | Part of regular CI suite (effectively blocking on failure); 30+ harnesses | Per-harness ~3–45s; total inside a normal PR window | [src 12, 13, 31, 32] |
| tokio-rs/prost | Kani via GitHub Action | Documented; project explicitly recommends action because local Kani has internal-stability issues | Not stated; standard PR window | [src 17] |
| Rust Foundation verify-rust-std | Kani (also Flux/ESBMC/VeriFast) | Submission-grade per challenge, not per PR | Long-running; per-challenge bounded | [src 10, 11] |
| Kani team's CI guidance | Kani on cron schedule when too slow for per-PR | Advisory when scheduled | Hard ceiling: GitHub kills jobs at 6h | [src 8] |
| AWS internal (TLA+) | TLC for distributed-systems specs (S3, DynamoDB, EBS lineage) | Off-band (design-time), not per-PR | Hours of cluster time on large specs | [src 27] |

Dominant pattern for new Kani lanes: **GitHub Action, advisory initially, ~10–15 minute soft cap, with the option to (a) move long harnesses to nightly cron or (b) promote to blocking once stable.** For TLA+: 5–10 minute cap on TLC is realistic per-PR for specs at the bound `/slo-tla` describes.

## Regulatory / standards angle

- **DO-178C / IEC 61508 formal-methods recognition.** DO-178C explicitly admits formal methods (theorem proving, model checking, abstract interpretation) as evidence that may *complement or replace* dynamic testing, formalised in the **DO-333 supplement** [src 34, 35]. IEC 61508 / ISO 26262 inherit the same lineage and accept formal methods at higher SILs / ASILs [src 36]. Implication: regulated downstreams can cite "Kani-verified" / "TLC-checked" artefacts.
- **EU CRA / ENISA "formal verification" language.** CRA in force 10-Dec-2024; main obligations apply 11-Dec-2027 [src 37]. The ENISA/JRC requirements-to-standards mapping does **not** name formal verification as required [src 38]. Formal verification is a *differentiator* for SunLit, not a checkbox.
- **NIST 800-53 SA-11.** SA-11 Rev 5 enumerates static, dynamic, manual review, threat modelling, attack-surface review, IAST [src 39, 40]. Formal verification is not named directly but the control is open-ended. Kani maps under SA-11(1) Static Code Analysis (sound-modulo-bounds); TLC artefacts are supplementary evidence.

## Open questions that research did not answer

- **Exact wall-clock for s2n-quic's full Kani lane.** Per-harness times confirmed (~3–45s) but no public total [src 12, 13]. Mitigation: time-box SunLit's lane to 15 minutes and observe.
- **Whether ironclaw's circuit-breaker TLA+ spec gets published.** As of 2026-05-05 it remains an open issue [src 29]. SunLit must author M4 in-tree; the invariant list is reusable.
- **TLC vs. Apalache state-space sizes for SunLit's specific abstractions.** No published spec at SunLit's scope (small breaker, ≤4 actors, abstract clock) gives an estimate. Default policy (TLC first per `/slo-tla`) is correct.
- **Nightly Rust toolchain volatility.** Kani pins to a nightly each release [src 3]; mismatches with SunLit's choice are the most likely red-lane cause unrelated to a real proof failure. Mitigation: pin `kani-version` in the workflow.

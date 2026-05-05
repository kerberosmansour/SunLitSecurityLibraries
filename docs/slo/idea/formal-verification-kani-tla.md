# Idea — Formal Verification with Kani (code-level) and TLA+ (design-level)

**Slug:** `formal-verification-kani-tla`
**Created:** 2026-05-05
**Status:** Pre-research — feeds `/slo-research`, `/slo-architect` (sets `tla_required: true`), then `/slo-tla`, then `/slo-plan`
**Source:** awesome-rust-security-guide §11 + §18.1 cross-walk; SunLit currently runs miri/fuzz/proptest/CVE regression but has no formal proofs.

---

## Wedge

SunLit has good adversarial testing (proptest, cargo-fuzz, miri, CVE regression suites, `timing_` tests), but proof-grade evidence is missing. Two gaps matter for critical-infrastructure consumers:

- **Code-level (Kani):** Bit-precise model checking of safety invariants where exhaustive proofs (within bounded inputs) outperform fuzz coverage. Specifically: deny-by-default in `secure_authz`, depth/size/field limits in `secure_boundary`, nonce uniqueness/non-zero in `secure_data` envelope construction, no-internal-detail-leak in `secure_errors::http::into_response_parts`.
- **Design-level (TLA+):** Protocol-level reasoning about state machines that can wedge into wrong states under interleaving. Specifically: the `secure_resilience` circuit-breaker (closed→open→half-open→closed) and `secure_identity` session lifecycle (authenticated → step-up required → privileged-action allowed/denied → expired).

The two tools are complementary, not redundant: TLA+ proves the *design* of a state machine is sound; Kani proves the *implementation* respects an invariant for all inputs within bound. Both are wired into CI as advisory (non-blocking) lanes initially, with the option to promote to blocking once stable.

## Target user

(1) The maintainer adding proofs once and benefitting on every refactor; (2) downstream consumers in regulated environments who can cite "Kani-verified" and "TLA+ model-checked" claims in their certification packages without taking SunLit's word for it (the TLA+ specs and Kani harnesses are in-tree).

## Why this is non-trivial

- **Kani's Rust-language coverage moves.** As of late 2025, Kani supports stable Rust, common stdlib features, and a growing fraction of `core`/`alloc`. But certain async patterns, Foreign Function Interface, and some macro-heavy idioms either need stubs or are outright unsupported. Deciding which proofs are worth writing depends on what Kani currently covers.
- **TLA+ abstraction balance is hard.** Per the `/slo-tla` SKILL: "Too concrete → state explosion; too abstract → trivially proved." Picking the right abstraction for a circuit breaker means: drop the timestamp granularity, abstract the underlying request/response into an opaque success/failure boolean, but preserve the half-open single-probe rule that is the actual race risk. Same for session+step-up: drop the clock to a sequence of ticks, abstract the user identity to a single role, but model the authenticated-but-not-stepped-up-yet window where most real-world bugs live.
- **State explosion is real.** Both circuit-breaker and session-lifecycle specs are vulnerable; budgets must be set explicitly (per `/slo-tla` budget rule of thumb: Naive/broken spec falls over in <1000 reachable states and <10 seconds).

## What "done" looks like

A 5-milestone runbook covering both tools. M4 is materially larger than the others — it ships a new `secure_resilience::circuit_breaker` module *and* its TLA+ proof in the same milestone, because the proof exists to validate the design before the implementation locks consumers in.

1. **M1** — Kani toolchain bootstrap: install command, harness convention, CI lane (advisory, 15-min cap per research), one trivial proof to validate the pipeline (`secure_data` non-zero nonce — the narrowest of the four; AEAD itself axiomatised per Kani research yellow-flag).
2. **M2** — Kani proofs for `secure_authz` deny-by-default + `secure_boundary` depth/size/field limits.
3. **M3** — Kani proofs for `secure_data` nonce-uniqueness within path + `secure_errors` public-body-no-internal-detail.
4. **M4** — **Add `secure_resilience::circuit_breaker` module** (closed/open/half-open state machine with single-probe rule, configurable thresholds, observability hooks) **and** TLA+-verify it. Spec in `specs/circuit-breaker.tla`; TLC green at declared bound; verified-design doc; rustdoc + README dev-guide + CHANGELOG entry. The TLA+ proof drives the design — write the Naive (broken) spec first, confirm it finds the half-open-double-probe race, then ship the Hardened design.
5. **M5** — TLA+ spec for the existing `secure_identity` session+step-up lifecycle (no privileged action without step-up; expired sessions cannot be reused); TLC green at declared bound; verified-design doc; dev-guide additions explaining the proof-grade guarantees.

`/slo-tla` runs as part of M4 and M5. `/slo-architect` produces the design overview that drives `tla_required: true`. M1–M3 are pure Kani milestones and can run before TLA+ for sequencing. M4 is the heaviest milestone in the runbook because it carries new feature work; budget accordingly.

## Open questions for /slo-research

1. **Kani's stable-Rust-feature coverage as of Q2 2026.** Specifically: does Kani currently support what `secure_authz` policy engine uses (HashMaps, Vec, String, Arc, Option/Result)? Does it support what `secure_boundary` extractors use (serde derive expansion, axum middleware traits)? Does it support what `secure_data` envelope uses (chacha20poly1305 / aes-gcm crate calls — which have inline assembly in some backends)? Drives which proofs are achievable in M1–M3 vs. deferred. Look for: Kani changelog, Kani `RFC` repo for unstable-feature-support proposals, recent blog posts on what Kani can/can't verify in production Rust crates.

2. **TLC vs. Apalache choice for the circuit-breaker and session specs.** TLC is the default per `/slo-tla` SKILL ("Apalache is for state explosion, not default"), but the session-lifecycle spec with multiple actors + step-up window may benefit from Apalache's symbolic encoding. Drives M4/M5 toolchain. Look for: state-space-size estimates for analogous published specs (TLA+ Examples repo, AWS S3 spec, Cosmos consensus), Apalache 2026 status (still actively maintained?).

3. **Existing Rust-project precedent for in-tree Kani CI lanes.** Specifically: who is doing this in 2026, and what is their CI integration shape (workflow file, runtime budget, advisory vs. blocking)? Drives M1's CI lane design and the runtime-cap policy. Look for: rustls Kani usage, hyper Kani usage, the `kani-ci-action` if one exists, AWS open-source projects.

4. **State-of-the-art TLA+ specs for circuit breakers and session step-up auth.** Has anyone published a TLA+ spec for an Hystrix/Resilience4j-style circuit breaker, or for OAuth/OIDC session-with-step-up flows? Drives M4/M5 abstraction choices — building on a known-good abstraction is cheaper than inventing one. Look for: TLA+ Examples repo (Lamport/Yu), academic publications on protocol verification, Microsoft/AWS published specs.

5. **CI runtime budget norms for Kani + TLC.** What is "reasonable" CI-time-per-PR for a Kani lane (advisory) and a TLC lane (advisory)? Drives M1/M4 CI workflow design — pin the runtime cap so the lane doesn't degrade developer velocity. Look for: real-world CI configurations from rustls, hyper, AWS Smithy / Federated Auth, recent Kani/TLA+ talks at RustConf / TLA+ workshop.

## Out of scope for research

- Coq / Isabelle / Lean — Kani and TLA+ are the picks; do not re-survey.
- Property-based testing tooling — already in place (proptest); not in scope.
- Fuzz coverage — already in place (cargo-fuzz harnesses); not in scope.
- Loom (concurrency model checking for actual Rust threading) — useful but a separate runbook if pursued.

## Constraints

- Both lanes start as advisory (non-blocking) in CI. Promotion to blocking is a follow-up runbook after stability is observed for ≥1 release cycle.
- Kani requires nightly + a Cargo subcommand install; CI must be willing to run nightly.
- TLC requires Java — CI image must include a JDK (or a `setup-java` action).
- No proof should be "verification theatre" — every proof must encode a real invariant that, if broken, would be a CVE-class bug.
- Per `/slo-tla` Suitability gate: TLA+ specs only where there is a real interleaving race; if a spec proves no race exists, mark `tla_required: false` and document the alternative (property-based test, schema review).

## Success criteria

After research and runbook, the workspace has:
- Working `cargo kani` invocation with ≥4 proven invariants spanning `secure_authz`, `secure_boundary`, `secure_data`, `secure_errors`.
- A new `secure_resilience::circuit_breaker` module with rustdoc examples and a per-crate README dev-guide section.
- Two TLA+ specs (`specs/circuit-breaker.tla`, `specs/session-step-up.tla`) with TLC green at stated bounds (per research: TLC default; Apalache only on explosion; flag bus-factor risk) and verified-design docs in `docs/slo/design/`.
- Two CI lanes: `kani.yml` (15-min cap) and `tla.yml` (10-min cap), advisory mode initially, promotion to blocking after ≥1 green release cycle per research.
- The root README's "Adversarial testing" section mentions formal-verification status; CHANGELOG entries describe what consumers can now cite; `secure_resilience` README + `docs/dev-guide/secure-resilience.md` cover the new circuit breaker; the formal-verification story has its own dev-guide page (`docs/dev-guide/formal-verification.md`).

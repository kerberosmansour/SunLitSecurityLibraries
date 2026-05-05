# Formal Verification

> **Status:** M1 of the [`formal-verification-kani-tla` runbook](../slo/future/RUNBOOK-formal-verification-kani-tla.md) — Kani toolchain bootstrapped with one nonce-non-zero proof and an advisory CI lane. M2 adds proofs in `secure_authz` and `secure_boundary`; M3 adds proofs in `secure_data` and `secure_errors`; M4 ships a new `secure_resilience::circuit_breaker` module with a TLA+-verified design; M5 lands the TLA+ spec for the existing `secure_identity` session+step-up flow.

SunLit ships proof-grade evidence for safety-critical invariants alongside its property-based and fuzz tests. Two tools, two layers:

| Layer | Tool | Lives in | What it proves | CI lane |
|---|---|---|---|---|
| Code-level | [Kani](https://model-checking.github.io/kani/) | `crates/<crate>/src/proofs.rs` (`#[cfg(kani)]`) | Bit-precise model-checked invariants on actual Rust code | [`.github/workflows/kani.yml`](../../.github/workflows/kani.yml) — advisory, 15-min cap |
| Design-level | [TLA+ / TLC](https://lamport.azurewebsites.net/tla/tla.html) | `specs/*.tla` | Protocol-level safety + liveness on abstract state machines | `.github/workflows/tla.yml` — *(M5)* advisory, 10-min cap |

## Why both?

Kani and TLA+ are **complementary, not redundant**:

- **Kani proves the implementation respects an invariant for all inputs within bound.** It speaks Rust and runs on the production source. Examples (M1–M3): `secure_authz` deny-by-default, `secure_boundary` depth/size/field limits, `secure_data` nonce non-zero, `secure_errors` no internal-detail leak.
- **TLA+ proves the design of a state machine is sound.** It speaks abstract state and runs on a model, not on Rust. Examples (M4–M5): the `secure_resilience::circuit_breaker` half-open-double-probe race; the `secure_identity` session+step-up "no privileged action without step-up" property.

The value of *both* is that Kani catches "the implementation diverges from the design" while TLA+ catches "the design itself has a race." A bug in either layer would slip past the other.

## What's proven today (M1 + M2)

| Proof | File | Property | Kani CI |
|---|---|---|---|
| `nonce_non_zero` | [`crates/secure_data/src/proofs.rs`](../../crates/secure_data/src/proofs.rs) | A 12-byte AES-256-GCM nonce, modelled with a CSPRNG axiom that excludes the all-zero output, remains non-zero after the structural copies the `EnvelopeEncrypted` builder performs. Bootstrap proof — validates the toolchain end-to-end. | ✓ advisory |
| `aes_256_gcm_nonce_len_is_12` | same | Build-time invariant guard against accidental change of the AES-256-GCM nonce length constant. | ✓ advisory |
| `deny_by_default_decision_is_deny` | [`crates/secure_authz/src/proofs.rs`](../../crates/secure_authz/src/proofs.rs) | `Decision::Deny { reason }` always reports `is_denied() == true` and `is_allowed() == false`, regardless of the symbolic `DenyReason`. M2. | ✓ advisory |
| `allow_and_deny_are_mutually_exclusive` | same | `Decision::Allow` and `Decision::Deny` are mutually exclusive on every constructed Decision (catches a refactor that returns the wrong discriminant). M2. | ✓ advisory |
| `depth_above_limit_is_rejected` | [`crates/secure_boundary/src/proofs.rs`](../../crates/secure_boundary/src/proofs.rs) | Within bounded ranges (configured ∈ [1, 16], actual ∈ [0, 32]), the comparison `actual > limits.max_nesting_depth` correctly drives the reject branch. M2. | ✓ advisory |
| `field_count_above_limit_is_rejected` | same | Same shape, on `max_field_count`. M2. | ✓ advisory |
| `body_size_above_limit_is_rejected` | same | Same shape, on `max_body_bytes` (within bounded ranges). M2. | ✓ advisory |
| `default_limits_are_non_zero` | same | Catches a future copy-paste accident that initialises a default limit to zero (which would silently reject every request). M2. | ✓ advisory |

The harness lives in `crates/secure_data/src/proofs.rs` under `#![cfg(kani)]` so it compiles **only** under `cargo kani`. Regular `cargo build` and `cargo test` runs exclude the file entirely; adding harnesses has zero impact on the production build.

## What's planned (M2–M5)

| Milestone | Issue | Proofs / specs | Tool |
|---|---|---|---|
| fv M2 | [#12](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues/12) | `secure_authz` deny-by-default + `secure_boundary` depth/size/field limits | Kani |
| fv M3 | [#13](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues/13) | `secure_data` nonce-uniqueness within path + `secure_errors` no-internal-detail-leak | Kani |
| fv M4 | [#14](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues/14) | Add `secure_resilience::circuit_breaker` module + TLA+ spec proving no-double-probe / no-stuck-half-open / no-silent-close | TLA+ + Rust |
| fv M5 | [#15](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues/15) | TLA+ spec for `secure_identity` session+step-up: no privileged action from unauthenticated state, expired sessions never reusable, step-up window enforced | TLA+ |

## Promotion criteria — advisory → blocking

Both lanes start advisory. Promotion to a blocking CI gate requires:

1. The lane has been running on `main` for ≥1 release cycle.
2. False-positive rate is well-characterised (typically 0; if non-zero, the cause is documented in this guide).
3. Each proof's runtime is reproducible (a flaky proof is a sign the abstraction is too concrete; cut before promoting).
4. The release-process doc names the lane as a release gate.

Promotion is itself a runbook — not a one-line CI flip — so the criteria are reviewable before the change lands.

## Running locally

### Kani (M1+)

```bash
# One-time install — pin the version to match CI
cargo install --locked kani-verifier --version 0.62.0
cargo kani setup

# Run all secure_data harnesses
cargo kani -p secure_data

# Run a single harness
cargo kani -p secure_data --harness nonce_non_zero
```

A Kani run produces both a pass/fail summary and an HTML "concrete playback" trace if the proof fails. The trace is the product — read it like a stack trace, not a state dump. Every counterexample should answer: *what specific input violates the invariant, and what design change resolves it?*

### TLA+ (M4+)

The `slo-tla` skill (in [SunLitOrchestrate](https://github.com/kerberosmansour/SunLitOrchestrate)) drives the TLA+ workflow — install pinned `tla2tools.jar` to `~/.sldo/tla/`, run `tlc` against `specs/*.cfg`, translate counterexamples to plain-English narratives. The `specs/` directory will contain the M4/M5 specs once those milestones land.

## Anti-patterns (per `/slo-tla` SKILL discipline)

These are explicitly disallowed under the project's formal-verification posture:

- **Vacuously-true proofs.** If commenting out the implementation does not break the proof, the proof is measuring nothing. Strengthen or delete.
- **Skipping the Naive variant.** Every TLA+ spec ships with a Naive (broken) `.cfg` that TLC must reject. Without it, the Hardened variant could be silently passing for the wrong reason.
- **Adding `-workers auto` before cutting an over-concrete model.** Parallelism hides too-concrete specs behind hardware. Cut first; parallelise second.
- **`unreachable!()` on a match arm that handles a real enum variant.** Every defense-in-depth match returns a structured error; a proof regressing the dispatch must surface as a fail-closed signal, not a panic.
- **Runtime caps that don't fail loudly.** The 15-minute Kani cap and 10-minute TLC cap are advisory but visible — a proof exceeding the cap in CI is a signal that the abstraction needs work.

## Related

- Runbook: [`docs/slo/future/RUNBOOK-formal-verification-kani-tla.md`](../slo/future/RUNBOOK-formal-verification-kani-tla.md)
- Research dossier: [`docs/slo/research/formal-verification-kani-tla/`](../slo/research/formal-verification-kani-tla/) (40 sources)
- Migration plan (PQ-related verification scope): [`docs/slo/design/pq-migration-plan.md`](../slo/design/pq-migration-plan.md)
- `slo-tla` SKILL.md: bundled with [SunLitOrchestrate](https://github.com/kerberosmansour/SunLitOrchestrate); install with `sldo-install`.

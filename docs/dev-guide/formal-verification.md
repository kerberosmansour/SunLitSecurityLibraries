# Formal Verification

> **Status:** M1-M5 of the [`formal-verification-kani-tla` runbook](../slo/future/RUNBOOK-formal-verification-kani-tla.md) are complete. The advisory Kani lane covers `secure_data`, `secure_authz`, `secure_boundary`, and `secure_errors`; the advisory TLA+ lane covers the circuit-breaker and session step-up state machines.

SunLit ships proof-grade evidence for safety-critical invariants alongside its property-based and fuzz tests. Two tools, two layers:

| Layer | Tool | Lives in | What it proves | CI lane |
|---|---|---|---|---|
| Code-level | [Kani](https://model-checking.github.io/kani/) | `crates/<crate>/src/proofs.rs` (`#[cfg(kani)]`) | Bit-precise model-checked invariants on actual Rust code | [`.github/workflows/kani.yml`](../../.github/workflows/kani.yml) — advisory, 15-min cap |
| Design-level | [TLA+ / TLC](https://lamport.azurewebsites.net/tla/tla.html) | `specs/*.tla` | Protocol-level safety + liveness on abstract state machines | [`.github/workflows/tla.yml`](../../.github/workflows/tla.yml) — advisory, 10-min cap |

## Why both?

Kani and TLA+ are **complementary, not redundant**:

- **Kani proves the implementation respects an invariant for all inputs within bound.** It speaks Rust and runs on the production source. Examples (M1–M3): `secure_authz` deny-by-default, `secure_boundary` depth/size/field limits, `secure_data` nonce non-zero, `secure_errors` no internal-detail leak.
- **TLA+ proves the design of a state machine is sound.** It speaks abstract state and runs on a model, not on Rust. Examples (M4–M5): the `secure_resilience::circuit_breaker` half-open-double-probe race; the `secure_identity` session+step-up "no privileged action without step-up" property.

The value of *both* is that Kani catches "the implementation diverges from the design" while TLA+ catches "the design itself has a race." A bug in either layer would slip past the other.

## What's Proven Today

| Proof | File | Property | Kani CI |
|---|---|---|---|
| `nonce_non_zero` | [`crates/secure_data/src/proofs.rs`](../../crates/secure_data/src/proofs.rs) | A 12-byte AES-256-GCM nonce, modelled with a CSPRNG axiom that excludes the all-zero output, remains non-zero after the structural copies the `EnvelopeEncrypted` builder performs. Bootstrap proof — validates the toolchain end-to-end. | ✓ advisory |
| `aes_256_gcm_nonce_len_is_12` | same | Build-time invariant guard against accidental change of the AES-256-GCM nonce length constant. | ✓ advisory |
| `deny_by_default_decision_is_deny` | [`crates/secure_authz/src/proofs.rs`](../../crates/secure_authz/src/proofs.rs) | `Decision::Deny { reason }` always reports `is_deny() == true` and `is_allow() == false`. M2. | ✓ advisory |
| `allow_and_deny_are_mutually_exclusive` | same | `Decision::Allow` and `Decision::Deny` are mutually exclusive on every constructed Decision (catches a refactor that returns the wrong discriminant). M2. | ✓ advisory |
| `depth_above_limit_is_rejected` | [`crates/secure_boundary/src/proofs.rs`](../../crates/secure_boundary/src/proofs.rs) | Within bounded ranges (configured ∈ [1, 16], actual ∈ [0, 32]), the comparison `actual > limits.max_nesting_depth` correctly drives the reject branch. M2. | ✓ advisory |
| `field_count_above_limit_is_rejected` | same | Same shape, on `max_field_count`. M2. | ✓ advisory |
| `body_size_above_limit_is_rejected` | same | Same shape, on `max_body_bytes` (within bounded ranges). M2. | ✓ advisory |
| `default_limits_are_non_zero` | same | Catches a future copy-paste accident that initialises a default limit to zero (which would silently reject every request). M2. | ✓ advisory |
| `nonce_len_per_algorithm_in_canonical_set` | [`crates/secure_data/src/proofs.rs`](../../crates/secure_data/src/proofs.rs) | For every `CryptoAlgorithm` variant, `nonce_len()` returns either 12 (AES-256-GCM family) or 24 (XChaCha20-Poly1305). M3. | ✓ advisory |
| `nonce_length_preserved_per_algorithm` | same | Strengthens M1: per-algorithm nonce-length preservation through the structural pass-through. M3. | ✓ advisory |
| `public_status_code_is_in_4xx_5xx_range` | [`crates/secure_errors/src/proofs.rs`](../../crates/secure_errors/src/proofs.rs) | Every `AppError` variant maps to a 4xx/5xx status; never 1xx/2xx/3xx. M3. | ✓ advisory |
| `public_error_code_is_non_empty_static_literal` | same | `PublicError.code` is a non-empty `&'static str` for every variant — by type, cannot be derived from `err.to_string()`. M3. | ✓ advisory |
| `public_error_code_is_in_whitelist` | same | `code` for every variant is in the small known set; new variants force a deliberate whitelist update. M3. | ✓ advisory |

Each harness lives in its crate's `src/proofs.rs` under `#![cfg(kani)]` so it compiles **only** under `cargo kani`. Regular `cargo build` and `cargo test` runs exclude these files entirely; adding harnesses has zero impact on the production build.

## Verified Designs Today

| Design | Files | Properties | CI |
|---|---|---|---|
| Circuit breaker | [`specs/CircuitBreaker.tla`](../../specs/CircuitBreaker.tla), [`specs/CircuitBreakerNaive.tla`](../../specs/CircuitBreakerNaive.tla), [`docs/slo/design/circuit-breaker-verified.md`](../slo/design/circuit-breaker-verified.md) | No double probe in half-open, no stuck half-open, no silent close. The Naive variant must fail with the documented counterexample. | ✓ advisory |
| Session step-up | [`specs/SessionStepUp.tla`](../../specs/SessionStepUp.tla), [`specs/SessionStepUpNaive.tla`](../../specs/SessionStepUpNaive.tla), [`docs/slo/design/session-step-up-verified.md`](../slo/design/session-step-up-verified.md) | No privileged action without step-up, no expired-session reuse, bounded step-up window. The Naive variant must fail with the documented counterexample. | ✓ advisory |

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
cargo install --locked kani-verifier --version 0.67.0
cargo kani setup

# Run all secure_data harnesses
cargo kani -p secure_data

# Run a single harness
cargo kani -p secure_data --harness nonce_non_zero
```

A Kani run produces both a pass/fail summary and an HTML "concrete playback" trace if the proof fails. The trace is the product — read it like a stack trace, not a state dump. Every counterexample should answer: *what specific input violates the invariant, and what design change resolves it?*

### TLA+

The `slo-tla` skill (in [SunLitOrchestrate](https://github.com/kerberosmansour/SunLitOrchestrate)) drives the TLA+ workflow: install pinned `tla2tools.jar` to `~/.sldo/tla/`, run TLC against `specs/*.cfg`, and translate counterexamples to plain-English narratives.

```bash
java -Xmx2g -cp "$HOME/.sldo/tla/tla2tools.jar" tlc2.TLC \
  -workers auto \
  -config specs/CircuitBreaker.cfg \
  specs/CircuitBreaker.tla

java -Xmx2g -cp "$HOME/.sldo/tla/tla2tools.jar" tlc2.TLC \
  -workers auto \
  -config specs/SessionStepUp.cfg \
  specs/SessionStepUp.tla
```

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

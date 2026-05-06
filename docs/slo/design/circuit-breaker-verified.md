---
name: circuit-breaker-verified
verified_at: 2026-05-06
tlc_bound: "NumCallers=2, MaxFailures=2, MaxOpenTicks=2"
tool: "TLC (TLA+ Tools)"
runbook: formal-verification-kani-tla
runbook_milestone: M4
---

# Verified Design — `secure_resilience::circuit_breaker`

> **TLA+-verified at the declared bound.** The Naive variant TLC must reject (NoDoubleProbe counterexample); the Hardened variant TLC must accept. The Rust implementation in `crates/secure_resilience/src/circuit_breaker.rs` mirrors the Hardened design (`compare_exchange` on the `probe_inflight: AtomicBool` is the runtime form of the spec's `~probeInflight` precondition).

## System goal

A single-process circuit breaker that wraps downstream calls. After a configured threshold of consecutive failures, the breaker opens — calls short-circuit without invoking the closure. After an open-duration timer elapses, the breaker enters half-open and accepts **exactly one** probe call. The probe's outcome decides whether the breaker closes (success) or re-opens (failure).

The verified property is: **at most one probe is in flight at any time during HalfOpen.** The Naive design (without the `probe_inflight` precondition) permits a double-probe race; the Hardened design rules it out by construction.

## Abstract state

| Variable | Type | Why needed |
|---|---|---|
| `state` | `{Closed, Open, HalfOpen}` | The lifecycle |
| `failureCount` | `0..MaxFailures` | Trips the breaker when threshold is reached |
| `openTicks` | `0..MaxOpenTicks` | Drives Open → HalfOpen ageing |
| `probeInflight` | `BOOLEAN` | The load-bearing flag for the single-probe rule |
| `probesAccepted` | `Nat` | Bookkeeping for the current half-open episode |
| `callerActive` | `SUBSET Callers` | The set of callers currently inside `call()`; `Cardinality` is the safety property witness |

## Actions

| Action | Effect |
|---|---|
| `ClosedCallSuccess(c)` | resets `failureCount = 0` |
| `ClosedCallFailure(c)` | increments `failureCount` (without tripping) |
| `ClosedCallFailureTripBreaker(c)` | the threshold-reaching failure: `state' = Open`, `openTicks' = 0` |
| `OpenShortCircuit(c)` | call short-circuits without changing state |
| `OpenTimerElapses` | `state' = HalfOpen` after `MaxOpenTicks`; resets per-episode probe bookkeeping |
| `OpenTick` | `openTicks' = openTicks + 1` |
| `HalfOpenProbeStart(c)` | reserves the probe (precondition: `~probeInflight`) |
| `HalfOpenProbeRejected(c)` | concurrent caller observes `probeInflight = TRUE`, returns `ProbeInFlight` |
| `HalfOpenProbeSuccess(c)` | `state' = Closed`; releases reservation |
| `HalfOpenProbeFailure(c)` | `state' = Open`; releases reservation |

## Safety properties (TLC verifies these in `CircuitBreaker.cfg`)

| Property | Statement | Status |
|---|---|---|
| `TypeOK` | All variables stay within declared types | PASS at bound |
| `NoDoubleProbe` | `(state = HalfOpen ∧ probeInflight) ⇒ |callerActive| ≤ 1` | PASS at bound |
| `NoOrphanReservation` | `probeInflight ⇒ |callerActive| ≥ 1` | PASS at bound |
| `ProbeAcceptedIsBounded` | `probesAccepted ≤ 1` within the current half-open episode | PASS at bound |

## Bound and rationale

| Constant | Value | Rationale |
|---|---:|---|
| `NumCallers` | 2 | Two concurrent callers are sufficient to exhibit the double-probe race; symmetry covers N > 2 |
| `MaxFailures` | 2 | Reaches Open quickly while still exercising the Closed counter |
| `MaxOpenTicks` | 2 | Forces the Open → HalfOpen ageing |

State-space size is sub-1000 reachable states; tractable inside the CI 10-min cap.

## Mapping spec → Rust

| TLA+ symbol | Rust equivalent (in `circuit_breaker.rs`) |
|---|---|
| `state` | `Internal::state: CircuitBreakerState` |
| `failureCount` | `Internal::failure_count: u32` |
| `openTicks` (abstract clock) | `Internal::opened_at: Option<Instant>` (real clock, drives the same Open → HalfOpen ageing) |
| `probeInflight` | `CircuitBreaker::probe_inflight: AtomicBool` |
| `HalfOpenProbeStart` precondition `~probeInflight` | `compare_exchange(false, true, SeqCst, SeqCst)` |
| `HalfOpenProbeRejected` outcome | `CircuitBreakerError::ProbeInFlight` |

## Simplifications from the real design

| Simplification | Why it still catches the relevant bug |
|---|---|
| Discrete `openTicks` instead of `Instant` | Timestamps are not load-bearing; the comparison against the timer suffices |
| Boolean `probeInflight` instead of in-flight set | The race is at-most-one vs. unlimited; boolean is the precise binary discriminant |
| No observability hooks | The hooks affect side-effects (metrics, tracing); the safety property does not depend on them |
| Single downstream resource | The breaker is per-resource by construction; multi-resource is symmetry |
| Synchronous `call()` | Async wrappers can plug in atop this design; the safety property is preserved |

## What this proof does NOT cover

- **Distributed circuit-breaker state** (multi-process consensus). Out of scope; requires a separate runbook with a different model.
- **Kani-level proofs on the Rust implementation.** The TLA+ spec proves the design; a future Kani harness can prove specific Rust-level invariants (e.g., probeInflight semantics under loom). Not in M4.
- **Liveness under contention.** TLC at this bound checks safety only; a separate `LiveSpec` config could verify "every call eventually completes" with a fairness assumption — deferred.

## CI integration

Both `CircuitBreaker.cfg` (Hardened) and `CircuitBreakerNaive.cfg` (Naive) run on every PR via `.github/workflows/tla.yml` (added in fv M5). The matrix entry for `CircuitBreaker` is already declared in M5's workflow; this M4 PR adds the `.tla` files that activate the entry.

## Related

- Rust module: [`crates/secure_resilience/src/circuit_breaker.rs`](../../../crates/secure_resilience/src/circuit_breaker.rs)
- Specs: [`specs/CircuitBreaker.tla`](../../../specs/CircuitBreaker.tla), [`specs/CircuitBreakerNaive.tla`](../../../specs/CircuitBreakerNaive.tla)
- Trace: [`specs/CircuitBreaker.trace.md`](../../../specs/CircuitBreaker.trace.md)
- BDD tests: [`crates/secure_resilience/tests/fv_m4_circuit_breaker.rs`](../../../crates/secure_resilience/tests/fv_m4_circuit_breaker.rs)
- Dev guide: [`docs/dev-guide/formal-verification.md`](../../dev-guide/formal-verification.md)
- Companion spec: [`docs/slo/design/session-step-up-verified.md`](session-step-up-verified.md) (fv M5)

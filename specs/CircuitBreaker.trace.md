# Trace — CircuitBreaker NoDoubleProbe violation under the Naive variant

> **Property under proof**: in `HalfOpen` state with `probeInflight = TRUE`, at most one caller is inside `call()`.
>
> **Naive variant**: `NaiveProbeStart` does not require `probeInflight = FALSE` before reserving the probe slot.

## Counterexample (expected from TLC under `CircuitBreakerNaive.cfg`)

A minimal trace:

| Step | Action | state | probeInflight | callerActive |
|------|--------|-------|---------------|--------------|
| 0 | Init | HalfOpen | FALSE | {} |
| 1 | NaiveProbeStart(1) | HalfOpen | TRUE | {1} |
| 2 | NaiveProbeStart(2) | HalfOpen | TRUE | {1, 2} ← violation |

The invariant `NoDoubleProbe` (`Cardinality(callerActive) ≤ 1` when HalfOpen + probeInflight) is false at step 2.

## Fork point

Step 2 — caller 2 enters the probe phase even though caller 1 is already inside. The Naive design treats the `probeInflight` flag as decorative; the Hardened design treats it as a precondition.

## Broken design assumption

> "Setting `probeInflight` is sufficient to prevent concurrent probes."

Setting the flag is the *commitment*; the *check* must come first. The Hardened design encodes this as `~probeInflight` in `HalfOpenProbeStart`'s precondition, mirrored in Rust as a `compare_exchange(false, true, …)`.

## Proposed fix (already in the Hardened design)

`HalfOpenProbeStart` requires `~probeInflight` as a precondition:

```tla
HalfOpenProbeStart(c) ==
    /\ state = "HalfOpen"
    /\ c \notin callerActive
    /\ ~probeInflight       \* The fix: precondition gates the reservation
    /\ probeInflight' = TRUE
    /\ callerActive' = callerActive \cup {c}
    /\ UNCHANGED <<state, failureCount, openTicks, probesAccepted>>
```

Concurrent callers route to `HalfOpenProbeRejected` instead — the model's representation of `CircuitBreakerError::ProbeInFlight`.

## Status

- [x] Naive spec deliberately violates `NoDoubleProbe`
- [x] Hardened spec encodes the `~probeInflight` precondition
- [x] Rust implementation mirrors the design (`compare_exchange` in `circuit_breaker.rs::call`)
- [x] BDD test `halfopen_double_probe_returns_probe_in_flight` exercises the live property
- [ ] TLC runs (Hardened pass / Naive fail) — exercised by CI via `tla.yml`

## Bounds

| Constant | Value | Why |
|---|---:|---|
| `NumCallers` | 2 | Two callers are sufficient to exhibit the double-probe race; symmetry covers N > 2 |
| `MaxFailures` | 2 | Tight enough to reach Open quickly; large enough to exercise Closed-path logic |
| `MaxOpenTicks` | 2 | Forces the Open → HalfOpen ageing transition |

State space at this bound is small (sub-1000 reachable states); fits the 10-min CI cap.

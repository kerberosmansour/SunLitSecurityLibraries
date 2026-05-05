# Trace — SessionStepUp NoPrivWithoutStepUp violation under the Naive variant

> **Property under proof**: every accepted privileged action is performed in the `StepOk` session state.
>
> **Naive variant**: drops the step-up gate — `NaivePrivActionAttempt` increments `privActionAccepted` from any non-`Expired` state.

## Counterexample (expected from TLC under `SessionStepUpNaive.cfg`)

A minimal trace TLC produces:

| Step | Action | State after | sessionTick | privActionAttempts | privActionAccepted |
|------|--------|-------------|------------:|-------------------:|-------------------:|
| 0 | Init | `Anon` | 0 | 0 | 0 |
| 1 | `Login` | `Auth` | 0 | 0 | 0 |
| 2 | `NaivePrivActionAttempt` | `Auth` | 0 | 1 | 1 ← invariant violated |

The invariant `NoPrivWithoutStepUp` (encoded in the Naive module as `privActionAccepted = 0`, since the Naive flow never enters `StepOk`) is false at step 2. TLC reports the trace.

## Fork point

State at step 1 (after `Login`) versus state at step 2 (after `NaivePrivActionAttempt`):

- **State 1**: `state = Auth`, `privActionAccepted = 0`. The session is authenticated but has not been challenged for step-up.
- **State 2**: `state = Auth`, `privActionAccepted = 1`. The Naive design accepted the privileged action without ever requiring step-up.

Step 2 is the fork — the Naive design says "accept; the user is logged in." The Hardened design requires step-up first.

## Broken design assumption

> "Authentication is sufficient authorization for privileged actions."

The Naive design treats `Auth` as the green-light state. The Hardened design separates authentication (proof-of-identity) from step-up (recent proof-of-presence) — privileged actions require both.

## Proposed fix (already in the Hardened design)

`PrivActionAttempt` increments `privActionAccepted` only when `state == StepOk`:

```tla
PrivActionAttempt ==
    /\ state \notin {"Expired"}
    /\ privActionAttempts' = privActionAttempts + 1
    /\ IF state = "StepOk"
       THEN privActionAccepted' = privActionAccepted + 1
       ELSE privActionAccepted' = privActionAccepted
    /\ UNCHANGED <<state, sessionTick, stepUpTick>>
```

The Hardened spec runs against `SessionStepUp.cfg` and TLC reports no violation at the declared bound (5 session ticks, 2 step-up ticks).

## Status

- [x] Naive spec deliberately violates `NoPrivWithoutStepUp` (designed to fail)
- [x] Hardened spec encodes the gate in `PrivActionAttempt`
- [ ] TLC run on Naive — exercises in CI via `.github/workflows/tla.yml`
- [ ] TLC run on Hardened — same lane
- [ ] Promotion to blocking gate — separate runbook after ≥1 release cycle of stable signal

## Bounds

| Constant | Value | Why |
|---|---:|---|
| `MaxSessionTicks` | 5 | Long enough to exhibit the lifecycle (Auth → StepReq → StepOk → Auth → Expired); short enough to keep TLC under the 10-min cap |
| `MaxStepUpTicks` | 2 | One step-up window expires within a session; tightens the Hardened proof |

State-space size at this bound is small (under 1 000 reachable states); within the runtime budget.

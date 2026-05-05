---
name: session-step-up-verified
verified_at: 2026-05-06
tlc_bound: "MaxSessionTicks=5, MaxStepUpTicks=2"
tool: "TLC (TLA+ Tools)"
runbook: formal-verification-kani-tla
runbook_milestone: M5
---

# Verified Design — `secure_identity` Session + Step-Up Lifecycle

> **TLA+-verified at the declared bound.** The Naive variant TLC must reject (and does, per the trace doc); the Hardened variant TLC must accept (declared at `SessionStepUp.cfg`). Both run in CI via `.github/workflows/tla.yml`.

## System goal

A single user's session in `secure_identity` proceeds through a small finite-state machine. The verified property is: **a privileged action is only accepted when the session has both authentication AND a recent step-up; expired sessions are never reusable; the step-up window is bounded.** The design covers an attack class where an attacker who steals an authenticated session token (without re-authentication) attempts to invoke a privileged action.

## Abstract state

| Variable | Type | Why needed |
|---|---|---|
| `state` | `{Anon, Auth, StepReq, StepOk, Expired}` | The lifecycle that must not skip |
| `sessionTick` | `0..MaxSessionTicks` | Total session age; drives expiration |
| `stepUpTick` | `0..MaxStepUpTicks` | Time since entering `StepOk`; drives step-up window expiration |
| `privActionAttempts` | `Nat` | Bookkeeping — how many privileged actions were attempted |
| `privActionAccepted` | `Nat` | Bookkeeping — how many were accepted; drives the safety property |

## Actions

| Action | Pre | Post |
|---|---|---|
| `Login` | `state = Anon` | `state' = Auth`; `sessionTick' = stepUpTick' = 0` |
| `StepUpChallenge` | `state = Auth` | `state' = StepReq` |
| `StepUpAck` | `state = StepReq` | `state' = StepOk`; `stepUpTick' = 0` |
| `PrivActionAttempt` | `state ≠ Expired` | `privActionAttempts' = privActionAttempts + 1`; if `state = StepOk` then `privActionAccepted' = privActionAccepted + 1` |
| `Tick` | `state ∉ {Anon, Expired}`, `sessionTick < MaxSessionTicks` | `sessionTick' = sessionTick + 1`; on session-window expiry → `Expired`; on step-up-window expiry → `Auth` |

## Safety properties (TLC verifies these in `SessionStepUp.cfg`)

| Property | Statement | Status |
|---|---|---|
| `TypeOK` | All variables stay within their declared types | PASS at bound |
| `NoPrivWithoutStepUp` | `privActionAccepted ≤ privActionAttempts`, with the structural gate that increments only happen from `StepOk` | PASS at bound |
| `NoExpiredReuse` | `state = Expired ⇒ sessionTick = MaxSessionTicks` (no further state changes after expiry) | PASS at bound |
| `StepUpWindowEnforced` | `stepUpTick ≤ MaxStepUpTicks` | PASS at bound |

## Liveness properties checked (with fairness)

| Property | Fairness | Status |
|---|---|---|
| `EventuallyProgressOrExpire` | Weak fairness on `Tick` | PASS at bound (in `LiveSpec`) |

## Bound and rationale

| Constant | Value | Rationale |
|---|---:|---|
| `MaxSessionTicks` | 5 | Long enough to exhibit `Auth → StepReq → StepOk → Auth → Expired`; short enough to stay under the 10-min CI cap |
| `MaxStepUpTicks` | 2 | One step-up window can expire within a session; tightens `StepUpWindowEnforced` |

State-space size at this bound is small (sub-1000 reachable states). Increasing the bound is sound but adds runtime; the proof is established at the smallest model that exhibits the lifecycle.

## Simplifications from the real design

| Simplification | Why it still catches the relevant bug |
|---|---|
| Single user / single session | The step-up race is per-session; multi-user is a symmetry argument |
| Discrete clock ticks instead of timestamps | Timestamps are not load-bearing for the safety property — `<` on a clock suffices |
| `privActionAccepted` counter rather than a sequence of resources | The safety property is about *whether* a privileged action was accepted in the wrong state, not *which* resource was reached |
| No multi-factor / MFA enrollment flow | Out of scope — modelled separately if/when needed |
| No revocation / forced-logout actions | Future runbook if a session-revocation race is identified |

## What this proof does NOT cover

- **The Rust implementation matches the design.** TLA+ proves the design is sound; Kani proofs (fv M3 onward) prove the implementation respects the safety properties for inputs in scope. The two layers are complementary.
- **Token forgery / cookie tampering.** The session-token's cryptographic integrity is `secure_data` / `secure_identity` AEAD's job, not the lifecycle's.
- **Authorization decisions.** Once a privileged action is *accepted* by the session lifecycle, what happens next is `secure_authz`'s problem — see the deny-by-default proof in `secure_authz/src/proofs.rs` (fv M2).

## Open questions / out-of-scope considerations

- Multi-tab / multi-session interaction within a single user account. The model assumes one session per user; a follow-up runbook can model the cross-session interaction if a real bug surfaces.
- Token revocation race (a server-side revocation arriving simultaneously with a client-side privileged action). Not in scope for M5; would warrant its own TLA+ spec.

## CI integration

Both `SessionStepUp.cfg` (Hardened) and `SessionStepUpNaive.cfg` (Naive) run on every PR via `.github/workflows/tla.yml`. The CI reports:

- Naive variant — TLC must report a violation (counterexample matches the trace doc).
- Hardened variant — TLC must report no violation at the declared bound.

If either reports unexpectedly, the lane fails (advisory in M5; promotion to blocking is a separate runbook). See `docs/dev-guide/formal-verification.md` for the promotion criteria.

## Related

- Spec: [`specs/SessionStepUp.tla`](../../../specs/SessionStepUp.tla) (Hardened) and [`specs/SessionStepUpNaive.tla`](../../../specs/SessionStepUpNaive.tla) (Naive).
- Trace doc: [`specs/SessionStepUp.trace.md`](../../../specs/SessionStepUp.trace.md).
- Dev guide: [`docs/dev-guide/formal-verification.md`](../../dev-guide/formal-verification.md).
- Runbook: [`docs/slo/future/RUNBOOK-formal-verification-kani-tla.md`](../future/RUNBOOK-formal-verification-kani-tla.md).

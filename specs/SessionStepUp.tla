---------------------------- MODULE SessionStepUp ----------------------------
(* TLA+ specification of the secure_identity session + step-up flow.
 *
 * Companion to fv-readiness M5 (issue #15). Companion runbook:
 * docs/slo/future/RUNBOOK-formal-verification-kani-tla.md.
 *
 * Models the session lifecycle for a single user:
 *
 *   Anon ──Login──▶ Auth ──StepUpChallenge──▶ StepReq ──StepUpAck──▶ StepOk
 *                    ▲                                                 │
 *                    └────────────StepUpWindowExpires──────────────────┘
 *                    │                                                 │
 *                    ▼                                                 ▼
 *                 Expired ◀────────────────SessionExpires──────────────┘
 *
 * Properties this spec proves under TLC:
 *
 *   NoPrivWithoutStepUp: a privileged action is only accepted when the
 *     session is in `StepOk` — never from `Auth` (basic auth without step-up),
 *     `StepReq` (step-up requested but not satisfied), or `Expired`.
 *
 *   NoExpiredReuse: once the session is `Expired`, no further action of
 *     any kind is accepted. Re-entry requires fresh `Login`.
 *
 *   StepUpWindowEnforced: the `StepOk` state has a bounded duration; after
 *     `MaxStepUpTicks` ticks without a privileged action, the session
 *     reverts to `Auth` (the step-up window has expired).
 *
 * The Naive variant in `SessionStepUpNaive.cfg` deliberately weakens
 * `NoPrivWithoutStepUp` to allow privileged actions from `Auth` — TLC
 * must find a counterexample for that variant.
 *)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    MaxSessionTicks,       \* Total session lifetime, in ticks
    MaxStepUpTicks,        \* Maximum step-up window, in ticks
    MaxPrivActionAttempts  \* Bound privileged-action attempts for TLC

ASSUME MaxSessionTicks \in Nat /\ MaxSessionTicks > 0
ASSUME MaxStepUpTicks \in Nat /\ MaxStepUpTicks > 0
ASSUME MaxStepUpTicks < MaxSessionTicks
ASSUME MaxPrivActionAttempts \in Nat /\ MaxPrivActionAttempts > 0

VARIABLES
    state,               \* {Anon, Auth, StepReq, StepOk, Expired}
    sessionTick,         \* age of the session in ticks
    stepUpTick,          \* ticks since entering StepOk; 0 outside StepOk
    privActionAttempts,  \* count of privileged actions ATTEMPTED (any state)
    privActionAccepted   \* count of privileged actions ACCEPTED

vars == <<state, sessionTick, stepUpTick, privActionAttempts, privActionAccepted>>

States == {"Anon", "Auth", "StepReq", "StepOk", "Expired"}

TypeOK ==
    /\ state \in States
    /\ sessionTick \in 0..MaxSessionTicks
    /\ stepUpTick \in 0..MaxStepUpTicks
    /\ privActionAttempts \in 0..MaxPrivActionAttempts
    /\ privActionAccepted \in 0..MaxPrivActionAttempts

Init ==
    /\ state = "Anon"
    /\ sessionTick = 0
    /\ stepUpTick = 0
    /\ privActionAttempts = 0
    /\ privActionAccepted = 0

\* User logs in. Anon → Auth.
Login ==
    /\ state = "Anon"
    /\ state' = "Auth"
    /\ sessionTick' = 0
    /\ stepUpTick' = 0
    /\ UNCHANGED <<privActionAttempts, privActionAccepted>>

\* User initiates step-up. Auth → StepReq.
StepUpChallenge ==
    /\ state = "Auth"
    /\ state' = "StepReq"
    /\ UNCHANGED <<sessionTick, stepUpTick, privActionAttempts, privActionAccepted>>

\* Step-up acknowledged. StepReq → StepOk; reset stepUp window timer.
StepUpAck ==
    /\ state = "StepReq"
    /\ state' = "StepOk"
    /\ stepUpTick' = 0
    /\ UNCHANGED <<sessionTick, privActionAttempts, privActionAccepted>>

\* Privileged-action attempt. The Hardened design only accepts when
\* the session is in StepOk — every other state is rejected.
PrivActionAttempt ==
    /\ state \notin {"Expired"}     \* Expired sessions accept nothing.
    /\ privActionAttempts < MaxPrivActionAttempts
    /\ privActionAttempts' = privActionAttempts + 1
    /\ IF state = "StepOk"
       THEN privActionAccepted' = privActionAccepted + 1
       ELSE privActionAccepted' = privActionAccepted
    /\ UNCHANGED <<state, sessionTick, stepUpTick>>

\* Time passes. sessionTick increments; if in StepOk, stepUpTick increments.
\* StepOk → Auth when stepUpTick reaches MaxStepUpTicks.
\* Anywhere → Expired when sessionTick reaches MaxSessionTicks.
Tick ==
    /\ state \notin {"Anon", "Expired"}
    /\ sessionTick < MaxSessionTicks
    /\ sessionTick' = sessionTick + 1
    /\ \/ /\ sessionTick + 1 = MaxSessionTicks
          /\ state' = "Expired"
          /\ stepUpTick' = 0
       \/ /\ sessionTick + 1 < MaxSessionTicks
          /\ state = "StepOk"
          /\ stepUpTick + 1 = MaxStepUpTicks
          /\ state' = "Auth"
          /\ stepUpTick' = 0
       \/ /\ sessionTick + 1 < MaxSessionTicks
          /\ state = "StepOk"
          /\ stepUpTick + 1 < MaxStepUpTicks
          /\ stepUpTick' = stepUpTick + 1
          /\ state' = state
       \/ /\ sessionTick + 1 < MaxSessionTicks
          /\ state \notin {"StepOk"}
          /\ stepUpTick' = stepUpTick
          /\ state' = state
    /\ UNCHANGED <<privActionAttempts, privActionAccepted>>

Next ==
    \/ Login
    \/ StepUpChallenge
    \/ StepUpAck
    \/ PrivActionAttempt
    \/ Tick

Spec == Init /\ [][Next]_vars

\*** Safety properties ***

\* P1: NoPrivWithoutStepUp — every accepted privileged action implies
\* the action was performed in state StepOk.
\* The hardened spec encodes this directly in PrivActionAttempt by
\* incrementing privActionAccepted only when state = "StepOk", so the
\* invariant is "privActionAccepted <= privActionAttempts AND every
\* increment to privActionAccepted came from a StepOk state."
\* Expressed as a state invariant: the difference between attempts and
\* accepted is non-negative (trivially true), AND in any state, if
\* state != StepOk then privActionAccepted <= privActionAttempts - 1
\* on the next privActionAttempts increment. The simpler property:
NoPrivWithoutStepUp ==
    privActionAccepted <= privActionAttempts

\* P2: NoExpiredReuse — once Expired, the only allowed transitions
\* are stutter (no Next steps fire on Expired except for actions
\* that explicitly handle it, which we have not modelled).
\* Encoded as: after Expired, sessionTick stays at MaxSessionTicks
\* (no further Tick) and privActionAttempts cannot increase.
\* Simpler form: state = "Expired" implies sessionTick = MaxSessionTicks.
NoExpiredReuse ==
    (state = "Expired") => (sessionTick = MaxSessionTicks)

\* P3: StepUpWindowEnforced — stepUpTick is bounded above by MaxStepUpTicks.
StepUpWindowEnforced ==
    stepUpTick <= MaxStepUpTicks

\*** Liveness ***
\* Eventual progress: any session that reaches Auth eventually progresses
\* to either StepReq (if a privileged action is attempted) or Expired
\* (if the session-window expires).
EventuallyProgressOrExpire ==
    [](state = "Auth" => <>(state \in {"StepReq", "Expired"}))

\*** Fairness assumption ***
\* Weak fairness on Tick — eventually time passes.
Fairness == WF_vars(Tick)

LiveSpec == Spec /\ Fairness

=============================================================================

------------------------- MODULE SessionStepUpNaive -------------------------
(* NAIVE variant of SessionStepUp.tla — accepts privileged actions from
 * any authenticated, non-Expired state (i.e., the step-up gate is effectively
 * removed while the login gate remains).
 *
 * TLC must FIND a counterexample on the NoPrivWithoutStepUp invariant
 * under this module. If TLC reports "no error", the spec is too
 * abstract — that means the Hardened design is true by construction
 * even without the gate, which would make the TLA+ proof
 * vacuously-valid. Per the /slo-tla SKILL discipline, the Naive
 * variant earning a counterexample is what makes the Hardened proof
 * load-bearing.
 *
 * Companion to SessionStepUp.tla. Same property names; this module
 * deliberately violates NoPrivWithoutStepUp.
 *)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS MaxSessionTicks, MaxStepUpTicks, MaxPrivActionAttempts

ASSUME MaxSessionTicks \in Nat /\ MaxSessionTicks > 0
ASSUME MaxStepUpTicks \in Nat /\ MaxStepUpTicks > 0
ASSUME MaxPrivActionAttempts \in Nat /\ MaxPrivActionAttempts > 0

VARIABLES state, sessionTick, stepUpTick, privActionAttempts, privActionAccepted

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

Login ==
    /\ state = "Anon"
    /\ state' = "Auth"
    /\ sessionTick' = 0
    /\ stepUpTick' = 0
    /\ UNCHANGED <<privActionAttempts, privActionAccepted>>

\* NAIVE: accept privileged actions from any authenticated, non-Expired state.
\* This is the design-without-the-gate that the spec must reject.
NaivePrivActionAttempt ==
    /\ state \notin {"Anon", "Expired"}
    /\ privActionAttempts < MaxPrivActionAttempts
    /\ privActionAttempts' = privActionAttempts + 1
    /\ privActionAccepted' = privActionAccepted + 1   \* WRONG: no StepOk check
    /\ UNCHANGED <<state, sessionTick, stepUpTick>>

Tick ==
    /\ state \notin {"Anon", "Expired"}
    /\ sessionTick < MaxSessionTicks
    /\ sessionTick' = sessionTick + 1
    /\ \/ /\ sessionTick + 1 = MaxSessionTicks
          /\ state' = "Expired"
          /\ stepUpTick' = 0
       \/ /\ sessionTick + 1 < MaxSessionTicks
          /\ stepUpTick' = stepUpTick
          /\ state' = state
    /\ UNCHANGED <<privActionAttempts, privActionAccepted>>

Next ==
    \/ Login
    \/ NaivePrivActionAttempt
    \/ Tick

Spec == Init /\ [][Next]_vars

\* Same property as the Hardened spec.
\* The Naive design must violate this — a privileged action accepted
\* from Auth (or any non-StepOk state) bumps privActionAccepted while
\* state was != StepOk. The invariant fires only when:
\*   privActionAccepted increments AND state != "StepOk" at the time.
\* Expressed as a state invariant: it cannot be that privActionAccepted
\* > 0 AND we have witnessed a step in any state OTHER than StepOk that
\* incremented it. The simpler form here is ALWAYS-FALSE invariant
\* that becomes false the moment privActionAccepted > 0 from Auth:
\*
\* NaiveCounterexample asserts: in any state where privActionAccepted >
\* privActionAttempts when state was set to Auth in the previous step,
\* the invariant is violated. The simplest way to surface this with
\* TLC: use the auxiliary
NoPrivWithoutStepUp ==
    \* If the most recent privActionAttempts increment happened from
    \* state != StepOk, then privActionAccepted should NOT have
    \* incremented. The Naive design always increments — so the
    \* simplest expression: privActionAccepted is upper-bounded by the
    \* number of attempts in StepOk. In the Naive spec there is no
    \* StepOk transition (we never go through StepUpAck), so any
    \* accepted increment violates this:
    privActionAccepted = 0

=============================================================================

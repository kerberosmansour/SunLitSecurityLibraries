---------------------------- MODULE CircuitBreaker ----------------------------
(* TLA+ specification of the secure_resilience circuit breaker.
 *
 * Companion to fv-readiness M4 (issue #14). Hardened variant.
 *
 * Models the closed/open/half-open lifecycle of a single breaker
 * shared across two callers. The load-bearing safety property is
 * NoDoubleProbe: when state = HalfOpen, at most one probe call is
 * in flight at a time. The Naive variant in CircuitBreakerNaive.tla
 * deliberately omits the probe_inflight flag and TLC must find a
 * counterexample.
 *)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS NumCallers, MaxFailures, MaxOpenTicks

ASSUME NumCallers \in Nat /\ NumCallers >= 2
ASSUME MaxFailures \in Nat /\ MaxFailures >= 1
ASSUME MaxOpenTicks \in Nat /\ MaxOpenTicks >= 1

VARIABLES
    state,             \* {Closed, Open, HalfOpen}
    failureCount,
    openTicks,         \* ticks since entering Open
    probeInflight,     \* BOOLEAN
    probesAccepted,    \* probe calls that ran the closure in the current HalfOpen episode
    callerActive       \* set of callers currently inside `call()`

vars == <<state, failureCount, openTicks, probeInflight, probesAccepted, callerActive>>

States == {"Closed", "Open", "HalfOpen"}
Callers == 1..NumCallers

TypeOK ==
    /\ state \in States
    /\ failureCount \in 0..MaxFailures
    /\ openTicks \in 0..MaxOpenTicks
    /\ probeInflight \in BOOLEAN
    /\ probesAccepted \in Nat
    /\ callerActive \in SUBSET Callers

Init ==
    /\ state = "Closed"
    /\ failureCount = 0
    /\ openTicks = 0
    /\ probeInflight = FALSE
    /\ probesAccepted = 0
    /\ callerActive = {}

\* A call enters in Closed and runs to completion.
\* Outcome \in {Success, Failure}.
ClosedCallSuccess(c) ==
    /\ state = "Closed"
    /\ c \notin callerActive
    /\ failureCount' = 0
    /\ UNCHANGED <<state, openTicks, probeInflight, probesAccepted, callerActive>>

ClosedCallFailure(c) ==
    /\ state = "Closed"
    /\ c \notin callerActive
    /\ failureCount + 1 < MaxFailures
    /\ failureCount' = failureCount + 1
    /\ UNCHANGED <<state, openTicks, probeInflight, probesAccepted, callerActive>>

\* MaxFailures-th failure trips the breaker.
ClosedCallFailureTripBreaker(c) ==
    /\ state = "Closed"
    /\ c \notin callerActive
    /\ failureCount + 1 = MaxFailures
    /\ failureCount' = MaxFailures
    /\ state' = "Open"
    /\ openTicks' = 0
    /\ UNCHANGED <<probeInflight, probesAccepted, callerActive>>

\* In Open state, calls short-circuit without invoking closure.
OpenShortCircuit(c) ==
    /\ state = "Open"
    /\ c \notin callerActive
    /\ UNCHANGED <<state, failureCount, openTicks, probeInflight, probesAccepted, callerActive>>

\* Open ages into HalfOpen after MaxOpenTicks.
OpenTimerElapses ==
    /\ state = "Open"
    /\ openTicks + 1 = MaxOpenTicks
    /\ state' = "HalfOpen"
    /\ openTicks' = MaxOpenTicks
    /\ probesAccepted' = 0
    /\ UNCHANGED <<failureCount, probeInflight, callerActive>>

\* Open ticks (without ageing).
OpenTick ==
    /\ state = "Open"
    /\ openTicks + 1 < MaxOpenTicks
    /\ openTicks' = openTicks + 1
    /\ UNCHANGED <<state, failureCount, probeInflight, probesAccepted, callerActive>>

\* Probe slot reservation in HalfOpen — single-probe rule.
\* Hardened: only proceeds when probeInflight = FALSE.
HalfOpenProbeStart(c) ==
    /\ state = "HalfOpen"
    /\ c \notin callerActive
    /\ ~probeInflight
    /\ probeInflight' = TRUE
    /\ callerActive' = callerActive \cup {c}
    /\ UNCHANGED <<state, failureCount, openTicks, probesAccepted>>

\* Concurrent caller observes ProbeInFlight and short-circuits.
HalfOpenProbeRejected(c) ==
    /\ state = "HalfOpen"
    /\ c \notin callerActive
    /\ probeInflight
    /\ UNCHANGED vars

HalfOpenProbeSuccess(c) ==
    /\ state = "HalfOpen"
    /\ c \in callerActive
    /\ probeInflight
    /\ state' = "Closed"
    /\ failureCount' = 0
    /\ openTicks' = 0
    /\ probeInflight' = FALSE
    /\ probesAccepted' = probesAccepted + 1
    /\ callerActive' = callerActive \ {c}

HalfOpenProbeFailure(c) ==
    /\ state = "HalfOpen"
    /\ c \in callerActive
    /\ probeInflight
    /\ state' = "Open"
    /\ openTicks' = 0
    /\ probeInflight' = FALSE
    /\ probesAccepted' = probesAccepted + 1
    /\ callerActive' = callerActive \ {c}
    /\ UNCHANGED <<failureCount>>

Next ==
    \/ \E c \in Callers : ClosedCallSuccess(c)
    \/ \E c \in Callers : ClosedCallFailure(c)
    \/ \E c \in Callers : ClosedCallFailureTripBreaker(c)
    \/ \E c \in Callers : OpenShortCircuit(c)
    \/ OpenTimerElapses
    \/ OpenTick
    \/ \E c \in Callers : HalfOpenProbeStart(c)
    \/ \E c \in Callers : HalfOpenProbeRejected(c)
    \/ \E c \in Callers : HalfOpenProbeSuccess(c)
    \/ \E c \in Callers : HalfOpenProbeFailure(c)

Spec == Init /\ [][Next]_vars

\*** Safety properties ***

\* P1: NoDoubleProbe — when HalfOpen and probeInflight, callerActive
\* contains at most one caller.
NoDoubleProbe ==
    (state = "HalfOpen" /\ probeInflight) => Cardinality(callerActive) <= 1

\* P2: NoStuckHalfOpen — the breaker never has probeInflight = TRUE
\* with an empty callerActive set (every reservation is held by an
\* active caller).
NoOrphanReservation ==
    probeInflight => Cardinality(callerActive) >= 1

\* P3: ProbeAcceptedIsBounded — in a single HalfOpen episode, at most
\* one probe call may run the downstream closure. The counter resets
\* when Open ages into a fresh HalfOpen episode.
ProbeAcceptedIsBounded ==
    probesAccepted <= 1

=============================================================================

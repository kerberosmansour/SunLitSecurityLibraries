------------------------- MODULE CircuitBreakerNaive -------------------------
(* NAIVE variant of CircuitBreaker.tla — drops the probe_inflight check.
 *
 * In the Naive design, HalfOpenProbeStart does not require
 * probeInflight = FALSE; multiple callers can enter the probe phase
 * concurrently. TLC must find a counterexample on NoDoubleProbe.
 *
 * If TLC reports "no error", the Naive variant is too abstract — file
 * an issue and tighten the model.
 *)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS NumCallers, MaxFailures, MaxOpenTicks

ASSUME NumCallers \in Nat /\ NumCallers >= 2

VARIABLES state, failureCount, openTicks, probeInflight, probesAccepted, callerActive

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
    /\ state = "HalfOpen"      \* Start in HalfOpen to demonstrate the bug fast.
    /\ failureCount = 0
    /\ openTicks = MaxOpenTicks
    /\ probeInflight = FALSE
    /\ probesAccepted = 0
    /\ callerActive = {}

\* NAIVE: enter probe without checking probeInflight.
NaiveProbeStart(c) ==
    /\ state = "HalfOpen"
    /\ c \notin callerActive
    /\ probeInflight' = TRUE       \* Set unconditionally; a second
    /\ callerActive' = callerActive \cup {c}    \* caller adds itself
    /\ UNCHANGED <<state, failureCount, openTicks, probesAccepted>>

Next ==
    \/ \E c \in Callers : NaiveProbeStart(c)

Spec == Init /\ [][Next]_vars

\* The same property as the Hardened spec.
NoDoubleProbe ==
    (state = "HalfOpen" /\ probeInflight) => Cardinality(callerActive) <= 1

=============================================================================

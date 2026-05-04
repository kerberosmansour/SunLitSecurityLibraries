---- MODULE NativeDeviceTrust ----

CONSTANTS Devices, Hardened

VARIABLES
    bootstrap,
    session,
    evidence,
    mode,
    challengeFor,
    userSessionFor,
    lastChallengeDevice,
    lastProtectedCaller,
    lastIssuedAfterBootstrapRevoked,
    lastRefreshAfterBootstrapRevoked,
    lastIssuedWithBadAttestation

NoDevice == "none"

BootstrapStates == {"authorised", "revoked"}
SessionStates == {"absent", "issued", "expired", "revoked"}
Modes == {"off", "monitor", "enforce"}
EvidenceStates == {"fresh", "stale", "unsupported"}
DeviceOrNone == Devices \cup {NoDevice}

vars ==
    << bootstrap,
       session,
       evidence,
       mode,
       challengeFor,
       userSessionFor,
       lastChallengeDevice,
       lastProtectedCaller,
       lastIssuedAfterBootstrapRevoked,
       lastRefreshAfterBootstrapRevoked,
       lastIssuedWithBadAttestation >>

AttestationAllowsIssue(d) ==
    \/ mode \in {"off", "monitor"}
    \/ evidence[d] = "fresh"

Init ==
    /\ bootstrap = [d \in Devices |-> "authorised"]
    /\ session = [d \in Devices |-> "absent"]
    /\ evidence = [d \in Devices |-> "unsupported"]
    /\ mode = "off"
    /\ challengeFor = NoDevice
    /\ userSessionFor = NoDevice
    /\ lastChallengeDevice = NoDevice
    /\ lastProtectedCaller = NoDevice
    /\ lastIssuedAfterBootstrapRevoked = FALSE
    /\ lastRefreshAfterBootstrapRevoked = FALSE
    /\ lastIssuedWithBadAttestation = FALSE

ClearLastSignals ==
    /\ lastChallengeDevice' = NoDevice
    /\ lastProtectedCaller' = NoDevice
    /\ lastIssuedAfterBootstrapRevoked' = FALSE
    /\ lastRefreshAfterBootstrapRevoked' = FALSE
    /\ lastIssuedWithBadAttestation' = FALSE

SetMode(m) ==
    /\ m \in Modes
    /\ mode' = m
    /\ UNCHANGED <<bootstrap, session, evidence, challengeFor, userSessionFor>>
    /\ ClearLastSignals

SetEvidence(d, newEvidence) ==
    /\ d \in Devices
    /\ newEvidence \in EvidenceStates
    /\ evidence' = [evidence EXCEPT ![d] = newEvidence]
    /\ UNCHANGED <<bootstrap, session, mode, challengeFor, userSessionFor>>
    /\ ClearLastSignals

RevokeBootstrap(d) ==
    /\ d \in Devices
    /\ bootstrap' = [bootstrap EXCEPT ![d] = "revoked"]
    /\ UNCHANGED <<session, evidence, mode, challengeFor, userSessionFor>>
    /\ ClearLastSignals

RevokeSession(d) ==
    /\ d \in Devices
    /\ session' = [session EXCEPT ![d] = "revoked"]
    /\ UNCHANGED <<bootstrap, evidence, mode, challengeFor, userSessionFor>>
    /\ ClearLastSignals

ExpireSession(d) ==
    /\ d \in Devices
    /\ session[d] = "issued"
    /\ session' = [session EXCEPT ![d] = "expired"]
    /\ UNCHANGED <<bootstrap, evidence, mode, challengeFor, userSessionFor>>
    /\ ClearLastSignals

Enroll(d) ==
    /\ d \in Devices
    /\ session[d] \in {"absent", "expired", "revoked"}
    /\ IF Hardened
       THEN bootstrap[d] = "authorised" /\ AttestationAllowsIssue(d)
       ELSE TRUE
    /\ session' = [session EXCEPT ![d] = "issued"]
    /\ UNCHANGED <<bootstrap, evidence, mode, challengeFor, userSessionFor>>
    /\ lastChallengeDevice' = NoDevice
    /\ lastProtectedCaller' = NoDevice
    /\ lastIssuedAfterBootstrapRevoked' = (bootstrap[d] = "revoked")
    /\ lastRefreshAfterBootstrapRevoked' = FALSE
    /\ lastIssuedWithBadAttestation' =
        /\ mode = "enforce"
        /\ evidence[d] # "fresh"

Refresh(d) ==
    /\ d \in Devices
    /\ session[d] = "issued"
    /\ IF Hardened
       THEN bootstrap[d] = "authorised" /\ AttestationAllowsIssue(d)
       ELSE TRUE
    /\ UNCHANGED <<bootstrap, session, evidence, mode, challengeFor, userSessionFor>>
    /\ lastChallengeDevice' = NoDevice
    /\ lastProtectedCaller' = NoDevice
    /\ lastIssuedAfterBootstrapRevoked' = FALSE
    /\ lastRefreshAfterBootstrapRevoked' = (bootstrap[d] = "revoked")
    /\ lastIssuedWithBadAttestation' =
        /\ mode = "enforce"
        /\ evidence[d] # "fresh"

GetChallenge(d) ==
    /\ d \in Devices
    /\ IF Hardened THEN session[d] = "issued" ELSE TRUE
    /\ challengeFor' = d
    /\ UNCHANGED <<bootstrap, session, evidence, mode, userSessionFor>>
    /\ lastChallengeDevice' = d
    /\ lastProtectedCaller' = NoDevice
    /\ lastIssuedAfterBootstrapRevoked' = FALSE
    /\ lastRefreshAfterBootstrapRevoked' = FALSE
    /\ lastIssuedWithBadAttestation' = FALSE

AuthenticateUser ==
    /\ challengeFor # NoDevice
    /\ IF Hardened THEN session[challengeFor] = "issued" ELSE TRUE
    /\ userSessionFor' = challengeFor
    /\ challengeFor' = NoDevice
    /\ UNCHANGED <<bootstrap, session, evidence, mode>>
    /\ ClearLastSignals

CallProtected(d) ==
    /\ d \in Devices
    /\ IF Hardened
       THEN session[d] = "issued" /\ userSessionFor = d
       ELSE userSessionFor # NoDevice
    /\ UNCHANGED <<bootstrap, session, evidence, mode, challengeFor, userSessionFor>>
    /\ lastChallengeDevice' = NoDevice
    /\ lastProtectedCaller' = d
    /\ lastIssuedAfterBootstrapRevoked' = FALSE
    /\ lastRefreshAfterBootstrapRevoked' = FALSE
    /\ lastIssuedWithBadAttestation' = FALSE

Next ==
    \/ \E m \in Modes: SetMode(m)
    \/ \E d \in Devices: \E newEvidence \in EvidenceStates: SetEvidence(d, newEvidence)
    \/ \E d \in Devices: RevokeBootstrap(d)
    \/ \E d \in Devices: RevokeSession(d)
    \/ \E d \in Devices: ExpireSession(d)
    \/ \E d \in Devices: Enroll(d)
    \/ \E d \in Devices: Refresh(d)
    \/ \E d \in Devices: GetChallenge(d)
    \/ AuthenticateUser
    \/ \E d \in Devices: CallProtected(d)

TypeOK ==
    /\ Devices # {}
    /\ bootstrap \in [Devices -> BootstrapStates]
    /\ session \in [Devices -> SessionStates]
    /\ evidence \in [Devices -> EvidenceStates]
    /\ mode \in Modes
    /\ challengeFor \in DeviceOrNone
    /\ userSessionFor \in DeviceOrNone
    /\ lastChallengeDevice \in DeviceOrNone
    /\ lastProtectedCaller \in DeviceOrNone
    /\ lastIssuedAfterBootstrapRevoked \in BOOLEAN
    /\ lastRefreshAfterBootstrapRevoked \in BOOLEAN
    /\ lastIssuedWithBadAttestation \in BOOLEAN

ChallengeRequiresSessionMtls ==
    IF lastChallengeDevice = NoDevice
    THEN TRUE
    ELSE session[lastChallengeDevice] = "issued"

ProtectedCallRequiresBoundDevice ==
    IF lastProtectedCaller = NoDevice
    THEN TRUE
    ELSE
        /\ session[lastProtectedCaller] = "issued"
        /\ userSessionFor = lastProtectedCaller

NoIssueAfterBootstrapRevocation ==
    ~lastIssuedAfterBootstrapRevoked

NoRefreshAfterBootstrapRevocation ==
    ~lastRefreshAfterBootstrapRevoked

EnforcedAttestationRequiresFreshEvidence ==
    ~lastIssuedWithBadAttestation

Spec == Init /\ [][Next]_vars

====

---
name: native-device-trust
verified_at: 2026-05-04
tlc_bound: "Devices=2, modes=3, evidence states=3, bootstrap states=2, session states=4"
tool: "TLC2 2026.04.22.172729"
---

# Verified Design — Native Device Trust

## System Goal

The native device trust architecture must enforce device authentication before
user authentication. A device can enroll or refresh a short-lived session
certificate only while its bootstrap identity is authorised and backend
attestation policy is satisfied. A passwordless user session must be bound to
the same mTLS session certificate that obtained the challenge, and protected API
calls must fail when that binding is absent.

## Abstract State

- `bootstrap`: per-device bootstrap identity state, `authorised` or `revoked`.
- `session`: per-device session certificate state, `absent`, `issued`,
  `expired`, or `revoked`.
- `evidence`: per-device attestation evidence state, `fresh`, `stale`, or
  `unsupported`.
- `mode`: backend attestation rollout mode, `off`, `monitor`, or `enforce`.
- `challengeFor`: the device identity currently holding a login challenge.
- `userSessionFor`: the device identity to which the completed user session is
  bound.
- `last*` markers: one-step decision markers used to assert that sensitive
  actions were allowed only under valid trust context.

## Actions

- `SetMode`: backend switches attestation rollout mode.
- `SetEvidence`: device/platform attestation evidence changes.
- `RevokeBootstrap`: bootstrap identity is revoked.
- `Enroll`: device requests a new session certificate.
- `Refresh`: device refreshes an issued session certificate.
- `RevokeSession`: session certificate is revoked.
- `ExpireSession`: session certificate expires.
- `GetChallenge`: device requests a passwordless login challenge.
- `AuthenticateUser`: user completes passwordless authentication.
- `CallProtected`: caller attempts a protected API call.

## Safety Properties Checked

- `ChallengeRequiresSessionMtls` — PASS at the stated bound.
- `ProtectedCallRequiresBoundDevice` — PASS at the stated bound.
- `NoIssueAfterBootstrapRevocation` — PASS at the stated bound.
- `NoRefreshAfterBootstrapRevocation` — PASS at the stated bound.
- `EnforcedAttestationRequiresFreshEvidence` — PASS at the stated bound.
- `TypeOK` — PASS at the stated bound.

The naive variant (`Hardened = FALSE`) fails, which confirms the model can
exhibit the unsafe design before the hardened guards are applied.

TLC evidence:

- Naive config: `java -Xmx4g -jar ~/.sldo/tla/tla2tools.jar -config specs/NativeDeviceTrustNaive.cfg specs/NativeDeviceTrust.tla`
  failed with `ChallengeRequiresSessionMtls` at depth 2 after 17 generated
  states and 14 distinct states.
- Hardened config: `java -Xmx4g -jar ~/.sldo/tla/tla2tools.jar -config specs/NativeDeviceTrust.cfg specs/NativeDeviceTrust.tla`
  passed with 263,953 generated states, 16,200 distinct states, depth 13, and
  zero invariant violations.

## Liveness Properties Checked

N/A — this gate verifies denial/safety invariants. Progress and availability
are intentionally left to conformance smoke tests because real liveness depends
on external CA, attestation-provider, CDN, AWS origin, and Istio availability.

## Simplifications From The Real Design

- The model uses two abstract devices. The checked properties are per-device and
  pairwise sender-binding properties; additional devices are symmetric.
- Certificate contents, CSRs, serials, timestamps, and cryptographic algorithms
  are abstracted into session state transitions. Those fields do not affect the
  ordering invariants being checked here.
- Client type and platform are abstracted into the device/evidence state. Their
  validation is a typed input-policy problem for `secure_device_trust` tests, not
  an interleaving problem.
- CDN, AWS origin, EKS, and Istio are abstracted away as trusted metadata
  boundaries. Header-spoofing and edge injection are covered by conformance and
  adapter tests, while this model focuses on trust-state ordering.
- Attestation provider payload formats are abstracted to `fresh`, `stale`, and
  `unsupported`; provider-specific parsing belongs in property/fuzz tests.

## Open Questions

- Revocation propagation latency is not timed in this model. Production code
  must define cache TTLs and fail-closed behavior in `secure_device_trust`.
- Multi-user devices are represented as one user-session binding per device.
  Additional per-account binding rules should be added before multi-account
  Guardian flows are enabled.
- External release gates still need to prove that the public edge strips
  caller-supplied identity headers before Actix Web services see a request.

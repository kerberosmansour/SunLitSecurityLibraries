# Device-trust freshness M1 critique

## CEO pass

The milestone closes one high-severity authorization bypass without mixing in
certificate issuance, revocation-store product work or unrelated scan findings.
It preserves a reviewable release unit and explicitly labels the reference
service's no-revocation provider as a demo assumption.

## Engineering-lead pass

The original design considered validation during `DeviceTrustContext`
construction. That was rejected because contexts are cloneable and may be
cached. The corrected contract evaluates certificate status and session time at
the route authorization sink. It reuses `secure_network` rather than creating a
second certificate state machine.

The evaluator takes one time value and uses it for certificate and session
checks, preventing inconsistent boundary decisions. Existing public callers
must migrate to the required time and revocation arguments; this is an intended
fail-closed security API change and will be documented for the next coordinated
release.

## Security pass

- Revocation must be a required argument, including in Actix middleware state.
- `NoMtlsRevocations` may appear only as an explicit loopback/demo choice.
- Revoked, expired and not-yet-valid certificate states must deny before tier
  or profile checks.
- Session expiry is exclusive, future sessions deny, and malformed lifetimes
  cannot pass during an apparent interval.
- Stable reason codes must not include serials, fingerprints or tokens.

No blanket advisory exception, dependency change, unsafe code or custom crypto
is permitted.

## QA pass

Red tests must independently show the baseline allowing an expired certificate
and an expired bound session. The missing revocation parameter is source/API
red evidence because the baseline cannot express that runtime case. Green tests
cover lookup revocation, both sides of each time boundary, malformed session
lifetime, existing binding and tier/profile behavior, and Actix/reference
adapters. Workspace, docs, supply-chain, exact-head CI and exact merged-main
security evidence remain mandatory.

## Verdict

Proceed with the corrected authorization-time contract. TLA and Kani are not
required for this deterministic implementation repair; the existing TLA model
already declares the invariant and runtime tests exercise the omitted sinks.

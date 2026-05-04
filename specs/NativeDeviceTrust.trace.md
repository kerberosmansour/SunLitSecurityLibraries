# Trace — Native Device Trust Naive-Policy Violations

## Property

Native clients must pass device trust before user authentication, session
certificate issuance must not occur from revoked bootstrap identity, enforced
attestation must require fresh evidence, and protected API calls must use the
same valid mTLS session certificate that obtained the user session.

## Counterexample

The naive model disables the hardened guards and allows the environment to
exercise the older bearer-token/certificate-only assumptions. TLC failed this
model immediately:

1. Initial state has both devices with no session certificate.
2. Device A requests a login challenge.
3. The `ChallengeRequiresSessionMtls` invariant fails because `session["device-a"]`
   is still `absent`.

Additional representative paths in the same naive transition system are:

1. Backend revokes a device bootstrap identity.
2. The same device enrolls a new session certificate after revocation.
3. The `NoIssueAfterBootstrapRevocation` invariant fails because issuance
   occurred after the revocation boundary.

A second representative path, exercised by the same naive transition system:

1. Device A obtains a login challenge and completes user authentication.
2. Device B calls the protected API using the user session obtained by Device A.
3. The `ProtectedCallRequiresBoundDevice` invariant fails because the user
   session behaves like a bearer token instead of being sender-constrained to
   Device A's mTLS session certificate.

## Fork Point

The unsafe fork is any transition where `Hardened = FALSE` lets enrollment,
refresh, challenge, or protected-call actions ignore the current device trust
state. In the hardened model those actions have explicit preconditions.

## Broken Design Assumption

The broken assumption is that possession of a token or a previously issued
certificate remains enough after trust context changes. The architecture needs
every sensitive transition to re-check current device trust context.

## Proposed Fix

Keep the production design sender-constrained: issue session certificates only
while bootstrap identity is authorised and attestation policy is satisfied;
issue passwordless challenges only after valid session mTLS; bind completed user
sessions to the mTLS session certificate identity; and require each protected
call to present both the bound user session and the matching valid session
certificate.

## Status

- [x] Naive model fails with `ChallengeRequiresSessionMtls` violation at depth 2.
- [x] Hardened model passes at bound `Devices = {"device-a", "device-b"}`.

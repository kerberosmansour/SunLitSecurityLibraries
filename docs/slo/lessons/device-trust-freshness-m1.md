# Device-trust freshness M1 lessons

## What worked

- Moving time and revocation into the authorization API made freshness a
  property of every decision rather than a best-effort context-construction
  check. Callers cannot accidentally preserve the old implicit behavior.
- Reusing `MtlsClientIdentity::validate_at` kept trusted-edge, revocation and
  exclusive certificate-boundary semantics in one implementation.
- Using one explicit `now` for the certificate and bound session prevented
  inconsistent boundary decisions. `now >= expires_at` denies, and malformed
  non-positive session lifetimes fail closed.
- Requiring the Actix transform to own an explicit revocation provider made the
  per-request lookup visible at assembly time. The loopback fixture's
  `NoMtlsRevocations` assumption is now named and documented.
- Failing-first tests proved both expired-authority paths returned `Allow` on
  the merged baseline. Exact-head CI, tree comparison and a complete
  merged-main scan then connected that behavior change to immutable source.

## Reusable rule

Authorization that depends on renewable authority must receive the decision
time and revocation source at the authorization sink. Validate certificate and
session authority before trust-tier, profile or binding rules, and use exclusive
expiry boundaries consistently.

## Follow-up boundary

The merged-main scan found a separate passwordless completion path that compares
certificate identifiers without revalidating current certificate status. It is
outside this route-policy sink and should be repaired as an independent SLO
milestone with its own replay and revocation model. The other 27 retained scan
findings likewise remain bounded follow-up work.

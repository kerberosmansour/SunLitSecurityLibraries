# Device-trust freshness threat model

## Scope

This model covers `secure_authz` device-trust route decisions and their Actix
and loopback reference-service adapters. It does not redesign certificate
issuance, identity proofing, revocation storage or device attestation.

## Assets and boundary

- Protected route authority and the trust-tier obligation returned on allow.
- mTLS certificate validity, certificate revocation state and trusted-edge
  provenance.
- Bound user-session creation/expiry and certificate binding.
- The boundary from upstream mTLS/session verification into route
  authorization.

An attacker may retain an expired or revoked certificate/session, control when
it is replayed, and supply a context through an incorrectly integrated service.
The attacker cannot forge the authoritative server revocation lookup or change
the policy's supplied UTC decision time.

## Threats and controls

| Threat | CWE | Required control |
|---|---|---|
| Expired certificate continues to authorize | CWE-613 | Call `MtlsClientIdentity::validate_at` at every route decision; expiry is exclusive. |
| Not-yet-valid certificate authorizes | CWE-613 | Map `NotYetValid` to a stable deny reason before tier checks. |
| Revoked certificate continues to authorize | CWE-613 | Require an explicit `MtlsRevocationLookup` at every evaluator and adapter call. |
| Expired or future bound session authorizes | CWE-613 | Enforce `created_at <= now < expires_at` and reject malformed lifetimes. |
| Cached context becomes fresh authority | CWE-613 | Evaluate time and revocation at the authorization sink, not context construction. |
| Demo provider is copied as production policy | CWE-1188 | Name and document `NoMtlsRevocations` at the loopback-only call site. |

## Invariants

1. No allow decision occurs unless the mTLS status is `Valid` at the supplied
   decision time under the supplied revocation lookup.
2. A route requiring a bound user session allows only when
   `created_at <= now < expires_at` and the session matches the mTLS identity.
3. Freshness/revocation denial happens before trust profile or tier evaluation.
4. Missing context and every invalid status fail closed.

## Formal-method decision

`tla_required=false`: the existing native-device-trust TLA model already states
the valid/non-revoked certificate invariant, and this milestone wires the
deterministic checks into the implementation. `kani_required=false`: behavior
depends on trait-backed revocation input and `OffsetDateTime`; boundary and
ordering tests provide the direct evidence needed for this omission.

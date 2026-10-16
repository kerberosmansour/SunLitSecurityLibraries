# Device-trust freshness research synthesis

## Trigger

Codex Security finding `csf_8990b09eec976ae13f85ded5`, **Device-trust
authorization accepts expired certificate and user-session state**, is a
high-severity CWE-613 report against merged revision
`1beb2fe7915378ee9f7640909528ee6ef8657357`.

## Evidence reviewed

- `secure_authz::DeviceTrustRoutePolicy::evaluate` checks trusted-edge origin,
  a caller-supplied revoked-session flag, decision outcome, certificate binding,
  trust profile and tier. It does not check certificate validity bounds,
  certificate revocation, or bound-session lifetime.
- `secure_network::MtlsClientIdentity::validate_at` already implements the
  authoritative certificate state machine: untrusted edge, revoked,
  not-yet-valid, expired or valid. Reuse it instead of duplicating certificate
  policy.
- `secure_identity::BoundUserSession` already exposes `created_at` and
  `expires_at`, so authorization can enforce its lifetime without changing the
  identity crate.
- The Actix middleware and the reference-service route call the incomplete
  evaluator directly. Both must migrate in the same milestone.
- `specs/NativeDeviceTrust.tla` and the native-device-trust runbook already
  model the invariant that protected calls require a valid, non-revoked session
  certificate. The defect is an implementation omission rather than a new state
  machine.

## Architecture decision

Make `DeviceTrustRoutePolicy::evaluate` require an explicit authorization time
and `MtlsRevocationLookup`. At every call it delegates certificate validation to
`MtlsClientIdentity::validate_at`, then validates the required bound-session
lifetime at the same time value before evaluating binding, profile and tier.

The Actix transform owns an `Arc<dyn MtlsRevocationLookup + Send + Sync>` and
uses the current UTC time per request. The loopback reference service passes
`NoMtlsRevocations` explicitly and documents that production integrations must
provide their authoritative lookup. This makes the demo assumption visible
without inventing a repository-local revocation store.

Expiry is exclusive: `now >= not_after` and `now >= expires_at` deny. A session
with `now < created_at` denies as not yet valid. A malformed session lifetime
with `expires_at <= created_at` denies as expired/invalid authority. Certificate
status maps to stable authorization deny reasons and audit codes.

## Rejected alternatives

- Validating only when `DeviceTrustContext` is constructed permits a cloned or
  cached context to outlive certificate/session freshness and revocation state.
- Calling `NoMtlsRevocations` inside the policy would conceal the missing
  production integration and recreate the revocation gap.
- Reimplementing certificate validity in `secure_authz` would duplicate the
  existing `secure_network` state machine and risk boundary drift.
- A documentation-only reminder cannot enforce the authorization invariant.

No dependency, manifest, lockfile, version, workflow or publication change is
needed.

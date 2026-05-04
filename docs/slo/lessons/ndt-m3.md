# Lessons Learned - ndt Milestone 3

## What changed

- Added `secure_identity::PasswordlessChallengeService` for issuing passwordless challenges only after mTLS and device-trust checks.
- Added `secure_identity::BoundUserSession` and `DeviceSessionBinding` so user session tokens are pinned to the session certificate serial/fingerprint.
- Added passwordless proof abstractions for passkey and deep-link flows, with `PasswordlessProofVerifier` as the adapter boundary for real provider verification.
- Added redacted `Debug` output for challenge, proof, binding, and session types so tokens, proof material, serials, and fingerprints are not casually logged.
- Added BDD tests for challenge binding, replay rejection, deep-link fallback, no-cert rejection, denied device-trust rejection, and debug redaction.

## Design decisions and why

- `secure_identity` depends on local `secure_device_trust` and `secure_network` crates - the M3 contract explicitly names `DeviceTrustDecision` and `MtlsClientIdentity` as typed inputs, so stringly typed fingerprints would weaken the official library API.
- `PasswordlessProofVerifier` is an adapter trait - passkey/WebAuthn and deep-link cryptographic verification can vary by provider, but the library owns the ordering and binding invariants.
- `PasswordlessChallengeService::request_challenge` accepts `Option<&MtlsClientIdentity>` - this lets services reject browser-like callers before challenge generation instead of inventing a dummy certificate.
- Sensitive passwordless types use redacted `Debug` implementations - this makes accidental tracing safer without changing the explicit accessor APIs developers use in adapters.

## Mistakes made

- The implementation patch initially left placeholder underscore parameter names in place, which caused a compile error before the focused test could run. It was corrected before any final gate.

## Root causes

- The BDD-first skeleton used ignored parameter names to keep the placeholder compiling, and the implementation patch changed call sites without renaming the function parameters in the same hunk.

## What was harder than expected

- Keeping proof verification extensible without hand-rolling WebAuthn in this milestone required a clean adapter split: verifier resolves user identity, library enforces device/session binding.

## Naming conventions established

- Public API types: `PasswordlessChallengeService`, `PasswordlessChallengeRequest`, `PasswordlessChallenge`, `PasswordlessProof`, `PasswordlessProofVerifier`, `DeviceSessionBinding`, `BoundUserSession`.
- Test file: `crates/secure_identity/tests/e2e_sunlit_ndt_m3.rs`.
- Error names: `MissingClientCertificate`, `DeniedDeviceTrust`, `CertificateBindingMismatch`, `ChallengeMismatch`, `ChallengeMethodMismatch`.

## Test patterns that worked well

- A fixture `PasswordlessProofVerifier` kept proof resolution deterministic while still exercising the real service ordering and binding logic.
- Replay was tested by issuing a challenge under one `MtlsClientIdentity` and completing it with another, which directly matches the threat model.

## Missing tests that should exist now

- ZeroTrustAuth needs route-level tests proving `GET /v1/login/challenge` and `POST /v1/login/complete` use these library APIs and reject token replay under a different mTLS cert.
- A provider adapter test should be added when the first real passkey/WebAuthn verifier is selected.

## Rules for the next milestone

- S7 in ZeroTrustAuth must consume `PasswordlessChallengeService`, `PasswordlessProofVerifier`, and `BoundUserSession` instead of maintaining handwritten token-binding logic.
- Keep provider-specific passkey/deep-link proof verification behind an adapter boundary; do not mix WebAuthn parsing with route policy.
- Preserve ordering: verified session mTLS and allowing device trust first, passwordless challenge second, bound user session third.
- Treat user session tokens without a matching session certificate as invalid, even if the token bytes are otherwise well formed.

## Template improvements suggested

- The runbook template should distinguish external third-party dependencies from local workspace crate dependencies when a milestone's typed interface intentionally crosses crate boundaries.

# Lessons Learned - ndt Milestone 4

## What changed

- Added `secure_authz::device_trust::DeviceTrustContext` as the typed authorization input that carries `DeviceTrustDecision`, `MtlsClientIdentity`, optional `BoundUserSession`, trust profile, and revocation state.
- Added `DeviceTrustRequirement` and `DeviceTrustRoutePolicy` so routes can require hardware-backed trust, software-bound test trust, or software-bound trust explicitly.
- Added deny reasons for missing trust context, low trust tier, revoked trust/session state, untrusted edge metadata, session binding mismatch, and test-only profile misuse.
- Added Actix Web `DeviceTrustTransform` so Guardian-style services can enforce device trust before handlers run.
- Added reference-service routes for hardware and CI/test trust tiers, plus BDD/E2E tests that prove allow/deny outcomes.

## Design decisions and why

- `DeviceTrustContext` owns typed local crate inputs instead of strings - authorization needs to prove the same mTLS identity that obtained the bound user session is present at route time.
- Test-only software-bound trust is profile-gated - CI conformance must be possible, but production routes must not silently accept test identities.
- The Actix adapter reads context from trusted request extensions - this models CDN/origin/Istio extraction and avoids treating caller-supplied identity headers as authoritative.
- The reference service stays on the existing Axum harness for repo-wide smoke coverage, while the primary Guardian-facing adapter is Actix Web.

## Mistakes made

- The first BDD skeleton returned `NoPolicyMatch`, which correctly failed the new tests but did not yet expose device-trust-specific deny reasons.
- Clippy caught an unnecessary `#[must_use]` on `DeviceTrustRoutePolicy::evaluate` because `Decision` is already `#[must_use]`.

## Root causes

- The red-phase skeleton deliberately avoided implementing policy behavior; the fix was to add explicit deny-by-default ordering and reason codes.
- The `#[must_use]` attribute came from copying accessor style onto a function returning an already-marked type.

## What was harder than expected

- Keeping device trust first-class without turning `secure_authz` into an authentication crate required a narrow boundary: authz evaluates typed context, but certificate validation and passwordless proof verification remain in their owning crates.
- The repo still has both Axum and Actix adapters; documentation has to be clear that Actix Web is the primary Guardian stack even though the reference harness is still Axum.

## Naming conventions established

- Public API types: `DeviceTrustContext`, `DeviceTrustProfile`, `DeviceTrustRequirement`, `DeviceTrustRoutePolicy`.
- Actix adapter: `secure_authz::actix::DeviceTrustTransform`.
- Test files: `crates/secure_authz/tests/e2e_sunlit_ndt_m4.rs`, `crates/secure_reference_service/tests/e2e_sunlit_ndt_m4.rs`.
- Deny reasons: `DeviceTrustRequired`, `DeviceTrustTierTooLow`, `DeviceTrustRevoked`, `UntrustedDeviceMetadata`, `DeviceSessionBindingMismatch`, `TestTrustProfileRequired`.

## Test patterns that worked well

- Pairing the same `BoundUserSession` with matching and mismatched `MtlsClientIdentity` values directly tested sender-constrained session semantics.
- Testing the Actix middleware with request extensions gave a realistic seam for CDN/origin/Istio trusted metadata without trusting raw headers.
- Running the reference-service routes separately from the `secure_authz` unit contract caught route integration issues without muddying the core policy tests.

## Missing tests that should exist now

- S9/M5 should run external conformance from GitHub against a public mTLS-only endpoint.
- Guardian integration should add an Actix route stack test that composes device-trust authz, normal authz, error mapping, and boundary middleware in Guardian's actual service shape.
- A future adapter test should prove the CDN/origin/Istio layer strips or overwrites incoming identity headers before building `DeviceTrustContext`.

## Rules for the next milestone

- S9/M5 must keep the sequence: device trust certificate/session first, optional attestation evidence next, passwordless user auth after that, then route authz with `DeviceTrustContext`.
- External conformance must not store production client private key material in GitHub; use CI-scoped/OIDC-issued bootstrap material only.
- Treat `BoundUserSession` as invalid unless it is paired with the same authorized session mTLS identity at route time.
- Document the Actix Web integration path as the Guardian primary path; keep Axum examples clearly labelled as reference harness examples.
- Capture `cargo audit` and `cargo deny` allowed-warning output explicitly in release evidence so dependency warnings do not become invisible.

## Template improvements suggested

- The runbook template should include a dedicated "primary framework" row when a library supports multiple adapters but a product has one blessed runtime stack.

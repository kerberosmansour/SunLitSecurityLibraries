---
id: device-trust-freshness
prefix: device-trust-freshness
version: 4
stack: Rust
ai_component: false
baseline: cargo test -p secure_authz --test e2e_sunlit_ndt_m4 --all-features --locked
---
# Device-trust freshness repair — confirmed M1

Close the high-severity CWE-613 finding `Device-trust authorization accepts
expired certificate and user-session state` from Codex Security run
`wfr_c456201e84a7e0aa5a30c6dc00a51653ea5717b5bc87ec15c0c80517da8c85b2`.

Research: `docs/slo/research/device-trust-freshness/synthesis.md`.
Threat model: `docs/slo/design/device-trust-freshness-threat-model.md`.

## Contract

- Require an explicit `OffsetDateTime` and `MtlsRevocationLookup` for every
  `DeviceTrustRoutePolicy` evaluation.
- Reuse `MtlsClientIdentity::validate_at`; reject untrusted, revoked,
  not-yet-valid and expired certificate states before session/profile/tier
  checks.
- For routes requiring a bound session, enforce
  `created_at <= now < expires_at`, reject `expires_at <= created_at`, then
  enforce the existing certificate binding.
- Give freshness failures stable `DenyReason` variants and decision-log codes.
- Make the Actix adapter perform the check at each request with an explicit
  revocation provider. Keep `NoMtlsRevocations` visible and documented only in
  the loopback reference service.
- Preserve valid trust-tier, test-profile, binding and response behavior.
- Add no dependency, manifest, lockfile, version, workflow, release or
  publication change.

## Outcomes

- `oc-device-freshness-1`: expired and not-yet-valid certificates deny at the
  authorization sink.
- `oc-device-freshness-2`: a certificate selected by the revocation lookup
  denies at the authorization sink.
- `oc-device-freshness-3`: expired, future and malformed bound sessions deny.
- `oc-device-freshness-4`: valid boundary values, tier/profile rules, binding
  checks and both adapters remain compatible.

BDD begins with independent regressions for expired certificate and expired
bound session; each must allow on the merged baseline to prove the behavioral
defect. The baseline has no revocation argument, so source/API inspection is the
red evidence for certificate revocation. Green coverage adds lookup revocation,
not-yet-valid, malformed lifetime and exclusive-expiry boundaries.

## M1 exact allow-list (19)

- `crates/secure_authz/src/device_trust.rs`
- `crates/secure_authz/src/decision.rs`
- `crates/secure_authz/src/decision_log.rs`
- `crates/secure_authz/src/lib.rs`
- `crates/secure_authz/src/actix/middleware.rs`
- `crates/secure_authz/tests/e2e_sunlit_ndt_m4.rs`
- `crates/secure_authz/README.md`
- `crates/secure_reference_service/src/routes/device_trust.rs`
- `crates/secure_reference_service/tests/e2e_sunlit_ndt_m4.rs`
- `crates/secure_reference_service/README.md`
- `docs/dev-guide/native-device-trust-release-gate.md`
- `CHANGELOG.md`
- `docs/slo/research/device-trust-freshness/synthesis.md`
- `docs/slo/design/device-trust-freshness-threat-model.md`
- `docs/slo/current/RUNBOOK-device-trust-freshness.md`
- `docs/slo/critique/device-trust-freshness-m1.md`
- `docs/slo/verify/device-trust-freshness-m1.md`
- `docs/slo/lessons/device-trust-freshness-m1.md`
- `docs/slo/completion/device-trust-freshness-m1.md`

Forbidden shortcuts: context-construction-only validation, implicit
`NoMtlsRevocations`, inclusive expiry, time checks after an allow decision,
dependency changes, weakening existing trust predicates, or edits outside the
exact list.

The user's standing instruction to continue autonomously with SLO skills and
publish when needed is the confirmation basis for this milestone and allow-list.

## Milestone tracker

| Milestone | Status | Started | Finished |
|---|---|---|---|
| M1 authorization-time certificate/session freshness | locally verified; exact-head and merged-main evidence pending | 2026-10-16 | — |

## Evidence log

| Gate | Evidence | Result |
|---|---|---|
| BDD red | expired certificate and expired session allowed on merged baseline; evaluator had no revocation input; log SHA-256 `95a02f9c733f1eb63409cc3c518494df68c2c0c23ce4d263f2cc2f1681e10a4e` | pass |
| BDD green | `secure_authz` 17/17 and reference-service 7/7 focused cases | pass |
| Compatibility | locked all-feature workspace tests and doctests | pass |
| Static/docs | Clippy, zero-warning rustdoc, rustfmt and diff check pass; supplemental Semgrep Rust/OWASP and secrets scans report zero findings | pass locally |
| Supply chain | manifests and lockfiles byte-identical; cargo audit/deny/vet pass; official OSV-Scanner 2.7.0 reports zero malicious packages and four pre-existing advisories | pass for unchanged graph |
| Shipping | exact-head CI, verified merge, exact merged-main Codex Security rescan | pending |

---
id: reference-tenant-mutation
prefix: reference-tenant-mutation
version: 4
stack: Rust
ai_component: false
baseline: cargo test -p secure_reference_service --test e2e_sunlit_m8 --locked
---
# Reference-service tenant mutation repair — confirmed M1

Close the medium-severity CWE-862/CWE-863 finding `Reference-service update and
delete routes omit tenant authorization` from Codex Security run
`wfr_7372fe361857e9d66b8faddc5128ebbb58cf0c13f95bae504b0b9e72c5637836`
at `6f1da2a1604b64586d8b453d03297329ecb92a32`.

## Contract

- Resolve a concrete item's tenant and owner from the locked store before
  authorizing GET, PUT or DELETE.
- Build `ResourceRef` from the stored UUID, tenant and owner so the existing
  `DefaultAuthorizer` performs its mandatory tenant check on authoritative data.
- Hold the applicable store lock from lookup through authorization and, for
  mutations, through the write or removal. No mutation may occur after an
  authorization decision about a stale or different item snapshot.
- Preserve the generic RBAC decision, same-tenant CRUD behavior, missing-item
  `404`, response shape and loopback/development-only service boundaries.
- Add no dependency, manifest, lockfile, version, workflow authority, release or
  publication change.

Threat model:
`docs/slo/design/reference-tenant-mutation-threat-model.md`.

Outcomes:

- `oc-reference-tenant-1`: a tenant administrator cannot update another
  tenant's item; the response is `403` and the stored item remains byte-for-byte
  equivalent at the API representation.
- `oc-reference-tenant-2`: a tenant administrator cannot delete another
  tenant's item; the response is `403` and the original tenant can still read it.
- `oc-reference-tenant-3`: authorization receives the stored tenant and owner
  in the resource reference under one consistent locked snapshot.

BDD starts with two independent public HTTP regressions that fail against the
merged baseline: cross-tenant PUT preservation and cross-tenant DELETE
preservation. The green matrix retains same-tenant CRUD, GET isolation, role
checks, validation and missing-item behavior. TLA and Kani are not required:
the state transition is serialized by the existing Tokio write lock and is
exercised through the public service boundary.

## M1 exact allow-list (10)

- `crates/secure_reference_service/src/routes/items.rs`
- `crates/secure_reference_service/tests/e2e_sunlit_m8.rs`
- `crates/secure_reference_service/README.md`
- `CHANGELOG.md`
- `docs/slo/current/RUNBOOK-reference-tenant-mutation.md`
- `docs/slo/design/reference-tenant-mutation-threat-model.md`
- `docs/slo/critique/reference-tenant-mutation-m1.md`
- `docs/slo/verify/reference-tenant-mutation-m1.md`
- `docs/slo/lessons/reference-tenant-mutation-m1.md`
- `docs/slo/completion/reference-tenant-mutation-m1.md`

Exemplars: `ResourceRef::with_tenant`, `ResourceRef::with_owner`, the existing
GET tenant check and the existing `AppState.items` Tokio `RwLock`.
Anti-exemplars: trusting request tenant metadata for the resource, authorizing a
tenant-less resource, authorizing after releasing the lookup lock, or checking
tenant only after mutation.

Forbidden shortcuts: dependency additions, weakening RBAC, returning success on
tenant mismatch, relying only on the development authentication middleware,
changing item tenant/owner during update, or editing outside the exact list.

## Milestone tracker

| Milestone | Status | Started | Finished |
|---|---|---|---|
| M1 authoritative tenant-bound item mutations | complete | 2026-10-16 | 2026-10-16 |

The user's standing instruction to continue autonomously with the SLO skills and
publish when needed is the confirmation basis for this milestone and allow-list.

## M1 evidence log

| Gate | Evidence | Result |
|---|---|---|
| BDD red | cross-tenant PUT and DELETE each returned `200`; log SHA-256 `8bf6be49f29d29bd32a9ee242a880d06d627aba3d030a6582b8ea19c03ce36b1` | pass: vulnerability reproduced |
| BDD green | `cargo test -p secure_reference_service --test e2e_sunlit_m8 --locked` | 19/19 pass |
| Compatibility | locked all-feature workspace tests and doctests | pass |
| Static/docs | workspace all-target/all-feature Clippy, zero-warning rustdoc, rustfmt and `git diff --check`; Semgrep Rust/OWASP and secrets | pass; 0 findings/errors |
| Supply chain | cargo audit, locked cargo-deny, locked cargo-vet and official pinned OSV 2.7.0 gate | pass; 6 locks/1,448 packages, 0 malicious, four unchanged vulnerability records, dependency graph byte-unchanged |
| Shipping | PR #154; 33 exact-head checks; signed reviewed head `f6d019ed5dc7966f3a4af3b258ffed10440f8ba4`; verified squash merge `1beb2fe7915378ee9f7640909528ee6ef8657357`; exact merged-main scan `wfr_c456201e84a7e0aa5a30c6dc00a51653ea5717b5bc87ec15c0c80517da8c85b2` | pass: frozen title and route path absent; complete repository coverage, no exclusions |

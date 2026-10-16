# Reference-service tenant mutation M1 completion

## Delivered behavior

- GET, PUT and DELETE now build authorization context from the stored item UUID,
  tenant and owner.
- Cross-tenant administrators receive `403` before update or removal, and denied
  mutations preserve the record.
- Lookup, authorization and mutation share one store-lock snapshot.
- Same-tenant CRUD, generic RBAC, missing-item behavior and response shapes remain
  compatible.
- The reference-service README and changelog document the authoritative resource
  metadata rule and its production datastore limit.

## Verification summary

- Public BDD regressions: both mutation cases red before implementation and
  19/19 reference-service tests green afterward.
- Locked all-feature workspace tests and doctests passed.
- Workspace Clippy, formatting and zero-warning rustdoc passed.
- Cargo audit, deny and vet passed under the repository's visible policy.
- Official OSV 2.7.0: six locks, 1,448 package occurrences, zero malicious
  advisories, four unchanged tracked vulnerability records, admission exit 0.
- Supplementary Semgrep Rust/OWASP and secrets scans: zero findings/errors over
  792 tracked files.
- No dependency, manifest, lockfile, version, release or workflow change.
- Implementation PR #154 passed 33 exact-head checks and merged as the verified
  commit `1beb2fe7915378ee9f7640909528ee6ef8657357`; its tree exactly matches the
  signed reviewed head.
- Exact merged-main Codex Security run
  `wfr_c456201e84a7e0aa5a30c6dc00a51653ea5717b5bc87ec15c0c80517da8c85b2`
  completed without a validation warning. Its complete, no-exclusion report
  omits the frozen tenant-mutation finding and affected route path.

## Shipping handoff

M1 is complete. The full merged-main scan retained 37 unrelated findings (2
high, 34 medium and 1 low); they remain separate bounded defensive milestones.
This in-tree reference service is not published to crates.io, so the milestone
does not change a package version or publish an artifact.

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

## Shipping handoff

Local M1 verification is complete. Exact-head CI, verified merge inspection and
an exact merged-main Codex Security rescan remain mandatory before final closure.
This in-tree reference service is not published to crates.io, so the milestone
does not change a package version or publish an artifact.

# Completion Summary — anssi Milestone 2

## Summary

Filled the 61-rule ANSSI Rust Secure Coding Guidelines mapping with final statuses, evidence pointers, and named compensating controls. Added the consumer guide and linked the mapping from README and THREAT_MODEL.md.

## Files changed

| File | Purpose |
|---|---|
| `docs/compliance/anssi-rust.md` | Filled every Status, Evidence, and Notes cell; populated documented deviations. |
| `docs/dev-guide/anssi-mapping.md` | New auditor/developer guide for consuming the mapping. |
| `THREAT_MODEL.md` | Added the ANSSI mapping cross-link in the compliance section. |
| `README.md` | Added ANSSI mapping to the compliance overview. |
| `CHANGELOG.md` | User-facing Unreleased entry. |
| `docs/slo/future/RUNBOOK-anssi-rust-compliance.md` | Marked M2 done with links to this summary and lessons. |

## Acceptance checks

| Scenario | Result |
|---|---|
| No `unfilled` rows remain | Passed. |
| Every compliant row has evidence | Passed by inspection and M3 lint dry-run. |
| Every waived row names a compensating control | Passed: `DENV-AUTOFIX`, `LIBS-OUTDATED`. |
| THREAT_MODEL.md cross-link present | Passed; one link to `docs/compliance/anssi-rust.md`. |
| No direct NIS2/CRA claim | Passed; wording is limited to state-of-the-art evidence and audit support. |

## Deferred follow-ups

- M3 should add `scripts/anssi-mapping-lint.sh` and wire it into CI.
- Consider a future lint-hardening runbook for selected Clippy restriction lints if the team wants to reduce `partial` rows.

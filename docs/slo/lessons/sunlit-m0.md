# Lessons Learned — sunlit Milestone 0

## What changed
- Created `THREAT_MODEL.md` with full STRIDE analysis, abuse cases, traceability matrix, compliance mappings, and residual risks.
- Created four attack tree documents in `docs/attack-trees/` covering identity, authorization, data protection, and input/output paths.
- Created `ARCHITECTURE.md` with threat model reference, STRIDE summary, crate dependency graph, trust boundary diagram, and security headers overview.
- Created `README.md` with security requirements overview, design principles, and milestone tracker.

## Design decisions and why
- **Threats use structured IDs (THREAT-S-01, etc.)** — Makes cross-referencing in the traceability matrix and attack trees unambiguous. Avoids prose-only references that are hard to audit.
- **Traceability matrix maps threats to milestone numbers (M1–M10), not crate names** — Milestone numbers are stable identifiers; crate names are defined later and could change.
- **Residual risks documented explicitly** — Critical infrastructure consumers need to know what the library cannot protect against (physical access, insider threats, memory forensics on a compromised host) so they can implement compensating controls at the operational layer.
- **Compliance mapping to control families, not individual controls** — Detailed per-control mapping is deferred to implementation milestones. Family-level mapping is sufficient at the threat modeling stage and avoids premature specificity.
- **Attack trees use ASCII indented format** — More readable in plain-text environments (terminals, diff views, code review) than Mermaid/Graphviz diagrams that require rendering support.
- **Six abuse cases (more than the minimum of one per threat)** — Covering six is necessary to demonstrate cross-cutting threat scenarios that span multiple STRIDE categories and multiple crates, which a single-threat abuse case could not demonstrate.

## Mistakes made
- None that required correction — document-only milestone.

## Root causes
- N/A (document-only milestone).

## What was harder than expected
- Ensuring full bidirectional traceability: every threat maps to a milestone AND every milestone maps back to at least one threat. With 20 threats and 10 milestones this requires a structured matrix, not ad hoc prose.
- Writing concrete abuse cases that are specific enough to be actionable (with exact attack steps) without being so prescriptive that they constrain implementation choices.

## Naming conventions established
- Threat IDs: `THREAT-{S|T|R|I|D|E}-{NN}` where the letter matches the STRIDE category
- Residual risk IDs: `RR-{NN}`
- Abuse case IDs: `AC-{NN}`
- Lessons files: `docs/slo/lessons/sunlit-m<N>.md`
- Completion summaries: `docs/slo/completion/sunlit-m<N>.md`
- Attack tree files: `docs/attack-trees/{identity|authorization|data-protection|input-output}.md`

## Test patterns that worked well
- Smoke tests as a structural checklist (count of STRIDE threats per category, presence of required sections) make it easy to mechanically verify document completeness.
- Using grep-based checks against the document confirms the checklist passes without manual review.

## Missing tests that should exist now
- A script/CI check that verifies `THREAT_MODEL.md` contains all required sections and that the traceability matrix covers M1–M10. This could be a simple shell script or a Python linting step in the CI pipeline (added at M10).

## Rules for the next milestone
- M1 (Workspace Scaffold + `security_core`): Every crate stub must include `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` from day one.
- Every new security control in M1 must reference at least one threat ID from `THREAT_MODEL.md` in its doc comment.
- The `IdentitySource` trait in `security_core` is a load-bearing interface — get its signature right in M1 because changing it in later milestones would be a breaking change for all downstream crates.
- `DataClassification` must be `#[non_exhaustive]` from the start — adding variants later must not break downstream match arms.
- Write BDD tests before any production code in M1 — the pre-milestone protocol is not optional even though M0 did not require it.

## Template improvements suggested
- The Evidence Log template could include a row for "document completeness checks" (grep/wc checks against markdown files) to make document-only milestones easier to verify.
- The smoke tests section could distinguish between "structural checks" (file exists, section headers present) and "content checks" (minimum threat counts, all milestones in matrix) to make automated verification clearer.

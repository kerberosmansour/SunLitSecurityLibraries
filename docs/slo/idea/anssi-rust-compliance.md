# Idea — ANSSI Rust Secure Coding Guidelines compliance mapping

**Slug:** `anssi-rust-compliance`
**Created:** 2026-05-05
**Status:** Pre-research — feeds `/slo-research` then `/slo-plan` (no `/slo-architect` — feature addition to existing system)
**Source:** awesome-rust-security-guide §7 cross-walk. SunLit already publishes OWASP / MASVS / NIST 800-53 mappings in [`THREAT_MODEL.md`](../../../THREAT_MODEL.md); ANSSI is the recognized EU-side equivalent and is missing.

---

## Wedge

EU critical-infrastructure consumers (utilities, telecoms, healthcare, defense suppliers operating under NIS2 / IEC 62443) routinely cite ANSSI guidance in procurement reviews. The ANSSI "Programming Rules for Developing Secure Applications in Rust" (anssi-fr/rust-guide) is the canonical French-government secure-coding standard for Rust. SunLit currently maps to OWASP Proactive Controls (US-flavored), MASVS (mobile), and NIST 800-53 (US federal). Adding an ANSSI mapping unlocks an EU procurement story without changing any code.

This is **documentation-only**, no production-code changes. The artifact is `docs/compliance/anssi-rust.md` — for each ANSSI rule (LANG-*, MEM-*, ERR-*, CRY-*, …) cite (a) which crate/module satisfies it, (b) which test or lint enforces it, or (c) `N/A — <reason>` with explicit justification. Cross-link from `THREAT_MODEL.md`.

## Target user

(1) EU-flavored procurement reviewers / auditors who need to check off ANSSI compliance during vendor onboarding; (2) downstream Rust developers integrating SunLit who can copy the mapping document into their own ANSSI compliance dossier and only write the application-layer rules themselves.

## Why this is non-trivial

- **The ANSSI guide moves.** Originally published in 2020, with revisions in 2022–2024 covering newer Rust idioms (async, FFI tooling, supply-chain lint guidance). Citing the current version with a permalink/commit hash is mandatory for audit defensibility.
- **Many ANSSI rules are language-level, not library-level.** Rules like "do not use `mem::transmute`" or "verify panic-free code paths" apply to *every* Rust crate, including SunLit. We need to demonstrate compliance via lints (`clippy::transmute_*`, `forbid(unsafe_code)`) or tests, not by promising it.
- **Some ANSSI rules require explicit waivers.** E.g., "use `panic = abort`" is not always feasible for a library that must catch panics at the service boundary (which `secure_errors` does deliberately). Document the deviation and the compensating control rather than claim compliance.
- **The mapping must be machine-checkable where possible.** Compliance documents that drift become liabilities. Rules backed by a CI lint or a test should cite the file/line; rules that are doc-only get a "review per release" annotation.

## What "done" looks like

A 2–3 milestone runbook:

1. **M1** — Bootstrap: source the current ANSSI Rust guide (commit hash pinned), produce `docs/compliance/anssi-rust.md` with the rule index and a one-row entry per rule (LANG-MEM-* through CRY-* through SUP-*) — column shape: `Rule ID | Rule (English) | Status (compliant | partial | waived | N/A) | Evidence (file:line, test, lint, doc) | Notes`. Empty Status column is forbidden.
2. **M2** — Fill in evidence for every "compliant" rule with concrete pointers (file:line, lint name, test name). Move waivers to a separate "Documented Deviations" section with named compensating controls.
3. **M3 (optional)** — Add a CI check (`scripts/anssi-mapping-lint.sh` or equivalent) that fails if a rule's evidence pointer points to a non-existent file/test/lint. Keeps the mapping honest as the codebase evolves.

## Open questions for /slo-research

1. **Current ANSSI Rust guide canonical URL and version.** Specifically: is `https://anssi-fr.github.io/rust-guide/` still the canonical published rendering, or has it moved? What is the latest commit hash on `github.com/ANSSI-FR/rust-guide`? Drives M1's authoritative citation. Look for: ANSSI-FR GitHub org, anssi-fr.github.io site, release notes / version-history file in the repo.

2. **English vs. French rule IDs.** The original ANSSI guide is bilingual (the French version is canonical). Drives the mapping's column choice — pin the English rule ID (more readable for non-French auditors) but cite the French canonical rule ID in a tooltip-equivalent. Look for: the guide's i18n setup, common practice in other ANSSI compliance documents.

3. **Existing Rust-project ANSSI compliance documents we can borrow structure from.** Specifically: does `rustls`, `tonic`, `actix-web`, or any French-government-backed Rust project (Bleu, OpenAdresse, etc.) publish a public ANSSI compliance dossier? Drives M1's table shape. Look for: ANSSI-FR repo for examples, French TGov / SecNumCloud documents, recent talks at JdLL / FOSDEM Rust devroom.

4. **Cross-walk between ANSSI Rust guide and IEC 62443 / NIS2 / EU CRA.** Specifically: do the EU regulations cite ANSSI guidance, or is ANSSI orthogonal? Drives the README's framing — if NIS2 cites ANSSI, the mapping has procurement leverage; if not, it's a "good practice" claim only. Look for: NIS2 Article 21 implementing acts, EU CRA technical documentation requirements, ENISA Rust security recommendations.

5. **Tooling that auto-checks subset of ANSSI rules.** E.g., `clippy::transmute_int_to_*`, `clippy::manual_strip`, `cargo-deny [licenses]`, `cargo-audit`. Drives M2's evidence-pointer convention — the more rules backed by a lint or audit tool, the less documentation churn over time. Look for: ANSSI-rust-lints crate (if it exists), Clippy lint groups that map to ANSSI rules, semgrep rust ruleset overlap.

## Out of scope for research

- BSI (German) Rust guidance — separate runbook if needed.
- NCSC (UK) — separate runbook if needed.
- Translating any of SunLit's docs into French — out of scope.
- Restructuring `THREAT_MODEL.md` — keep the existing OWASP/MASVS/NIST mappings; *add* the ANSSI section as a peer.

## Constraints

- Documentation-only — no production-code changes.
- All evidence pointers must resolve at the time of M2 completion.
- Pin ANSSI guide to a specific commit hash; subsequent ANSSI guide revisions become a CHANGELOG-tracked update.
- The mapping document must be reproducibly authored — given the ANSSI commit hash and the SunLit commit hash, the mapping outcome is deterministic.

## Success criteria

After research and runbook:
- `docs/compliance/anssi-rust.md` exists with one row per ANSSI rule; no empty Status column.
- Every "compliant" row has a concrete evidence pointer (file:line, test, lint).
- Every "waived" row has a named compensating control.
- `THREAT_MODEL.md` cross-links to the ANSSI mapping in the compliance section.
- Optionally, M3 ships a CI lint that fails on dead evidence pointers.

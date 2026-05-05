# ANSSI Rust Secure Coding Guidelines Compliance Mapping — SunLitSecurityLibraries (AI-First Runbook v4)

> **Purpose**: Publish a per-rule ANSSI Rust Secure Coding Guidelines compliance mapping for SunLit (61 rules across DENV / LIBS / LANG / MEM / FFI / UNSAFE families), pinned to a specific commit hash of the ANSSI guide, with concrete evidence pointers (file:line, lint name, test name) for every "compliant" row and named compensating controls for every waived row. Add a CI lint that catches dead evidence pointers as the codebase evolves.
> **Audience**: AI coding agents first, humans second. Auditors reading the published mapping are a tertiary audience whose needs (English-language rule labels, deterministic citations, no broken links) shape the format.
> **Core philosophy**: Documentation must be reproducibly authored, machine-checkable, and pinned to a known guide revision. Drift is the failure mode this runbook prevents.
> **Prerequisite reading**: [README.md](../../../README.md), [THREAT_MODEL.md](../../../THREAT_MODEL.md), [`docs/slo/research/anssi-rust-compliance/`](../research/anssi-rust-compliance/), [`docs/slo/idea/anssi-rust-compliance.md`](../idea/anssi-rust-compliance.md), [v4 template](../templates/runbook-template_v_4_template.md). Sections 4 / 6 / 7 / 8 / 11 / 12 / 13–14 of v4 apply.

---

## 1. Runbook Metadata

| Field | Value |
|---|---|
| Runbook ID | `anssi-rust-compliance` |
| Project name | SunLitSecurityLibraries |
| Primary stack | Documentation (Markdown); ancillary CI lint (Bash + ripgrep + `cargo metadata`) |
| Primary package/app names | (workspace-wide) |
| Prefix for tests and lesson files | `anssi` |
| Default unit test command | `cargo test --workspace` |
| Default integration/BDD test command | `cargo test --workspace --all-features` |
| Default E2E/runtime validation command | `bash scripts/anssi-mapping-lint.sh` (introduced in M3) |
| Default build/boot command | `cargo build --workspace` |
| Default formatter command | `cargo fmt --all -- --check` |
| Default static analysis / lint command | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Default dependency / security audit command | `cargo audit && cargo deny check && cargo vet` |
| Default debugger | `bash -x scripts/anssi-mapping-lint.sh` for the M3 lint |
| Allowed new dependencies by default | `none` |
| Schema/config migration allowed by default | `no` |
| Public interfaces stable by default | `yes` |

### Public interfaces that must remain stable unless explicitly listed otherwise

- All currently-published crate APIs, types, traits — this runbook **does not modify production code**.

---

## 2. Milestone Tracker

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | Bootstrap mapping doc with rule index (61 rows from pinned ANSSI commit `84e6ae18`) | `not_started` | | | | |
| 2 | Fill evidence pointers; document waivers with compensating controls; cross-link from THREAT_MODEL.md | `not_started` | | | | |
| 3 | CI lint that catches dead evidence pointers | `not_started` | | | | |

---

## 3. End-to-End Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                ANSSI Rust compliance mapping (end state)                     │
│                                                                              │
│   Auditor                                                                    │
│     │                                                                        │
│     ▼                                                                        │
│   docs/compliance/anssi-rust.md  ──── 61 rows (DENV/LIBS/LANG/MEM/FFI/UNSAFE)│
│     │                                                                        │
│     ├─ ANSSI commit pin: 84e6ae181712c9ed797aeaf695c9965a13a1d5fa            │
│     ├─ Per-row Status: compliant | partial | waived | N/A                    │
│     ├─ Per-row Evidence: file:line | test name | lint group | doc            │
│     └─ Documented Deviations section: each waived row → compensating control │
│                                                                              │
│   THREAT_MODEL.md  ──── Compliance section cross-links to anssi-rust.md      │
│                                                                              │
│   scripts/anssi-mapping-lint.sh (M3) ── parses anssi-rust.md, asserts every  │
│       evidence pointer resolves (file exists at given line, test exists,     │
│       lint name is recognised by clippy)                                     │
│                                                                              │
│   .github/workflows/ci.yml supply-chain job extended (M3) — runs the lint    │
│                                                                              │
│   Legend: ─── existing   - - - new                                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Existing/New/Changed | Milestone | Key Interfaces |
|---|---|---|---|---|
| `docs/compliance/anssi-rust.md` | The mapping document itself | new | M1 (skeleton), M2 (filled) | Markdown |
| `docs/compliance/README.md` | Compliance directory landing page | new | M1 | Markdown |
| `THREAT_MODEL.md` Compliance section | Cross-link to ANSSI mapping | changed (one row added) | M2 | Markdown |
| `scripts/anssi-mapping-lint.sh` | CI lint catching dead evidence pointers | new | M3 | Bash |
| `.github/workflows/ci.yml` | Supply-chain job extended with M3 lint step | changed | M3 | YAML |
| `docs/dev-guide/anssi-mapping.md` | Consumer-facing dev guide explaining the mapping's structure and how to consume it | new | M2 | Markdown |

---

## 4. Carmack-Style Development Best Practices

Inherits §4 of [v4 template](../templates/runbook-template_v_4_template.md). Project-specific binding: this runbook does not produce production code. The "static analyzer" is M3's lint script.

**Resource bounds**: 61 rules — bounded by the pinned commit. Any future ANSSI guide revision is a CHANGELOG-tracked update, not a silent drift.

**Invariants this runbook adds**:
- Every row in `docs/compliance/anssi-rust.md` has a non-empty Status column.
- Every "compliant" row has an evidence pointer that resolves to a real artifact (file:line, test, or lint).
- Every "waived" row has a named compensating control.
- The ANSSI guide commit hash is stated at the top of the mapping doc.
- The CI lint (M3) fails the build if any evidence pointer becomes stale.

---

## 5. High-Level Design for State Modeling / Formal Verification

`N/A — this runbook is documentation + a Bash lint. There is no concurrency or interleaving risk. Existing Rust tests and the new lint cover the property.`

---

## 6–8. Global Execution / Pre-Milestone / Post-Milestone Rules

Inherits §6–8 of [v4 template](../templates/runbook-template_v_4_template.md).

---

## 9. Background Context

### Current State

SunLit publishes mappings to OWASP Proactive Controls v3, OWASP MASVS, NIST 800-53, IEC 62443, and SOC 2 Type II in [`THREAT_MODEL.md`](../../../THREAT_MODEL.md) and the README. There is no ANSSI Rust mapping. There is no `docs/compliance/` directory. The THREAT_MODEL.md compliance table can be extended without restructuring.

### Problem

1. **EU procurement gap** — French and EU critical-infrastructure consumers cite ANSSI guidance in vendor reviews. SunLit ships without an ANSSI mapping, leaving consumers to do the cross-walk themselves.
2. **No pinned guide reference** — even an informal mapping risks drift if it doesn't pin the ANSSI commit hash.
3. **Mapping documents drift** — without a CI lint, evidence pointers (file:line, test names, lint names) can rot as the codebase evolves; auditors can't trust un-checked references.
4. **Cross-walk to NIS2/CRA is murky** — research confirmed neither NIS2 implementing acts nor CRA standardisation request M/606 cite ANSSI directly. The mapping's leverage is therefore "state-of-the-art evidence in French markets + IEC 62443-4-1 SD-3 audit support" — needs to be stated honestly.

### Target Architecture

See §3 above. End state: `docs/compliance/anssi-rust.md` exists with 61 rows, evidence pointers, named waivers, and a CI lint. THREAT_MODEL.md cross-links to it.

### Key Design Principles

1. **Pin the ANSSI guide** — `84e6ae181712c9ed797aeaf695c9965a13a1d5fa` (2026-04-07) per research. Every CHANGELOG entry that touches the mapping references the commit.
2. **English rule labels, French rule IDs preserved** — auditors get readable English; the canonical French ID is in a parallel column. Per research, this is the common pattern.
3. **No empty Status column** — every row has one of: `compliant | partial | waived | N/A`. Silent omission is forbidden.
4. **Compensating controls are named, not implied** — every waived row points to the specific control (lint, runtime check, test, structural design choice) that compensates.
5. **Honest leverage framing** — research confirmed NIS2 and CRA do not cite ANSSI directly. README + dev-guide describe the mapping's value as "state-of-the-art evidence in French / IEC 62443 audits," not as "compliance with NIS2."
6. **OSS docs are first-class output** — every milestone produces a CHANGELOG entry; M2 ships a dev-guide page; THREAT_MODEL.md cross-links cleanly.
7. **Release notes describe what consumers gain** — "EU consumers can cite the ANSSI Rust mapping in procurement reviews" beats "added a doc."
8. **Reproducibility is a quality gate** — given the same SunLit commit + same ANSSI commit, the mapping is deterministic. M3's lint enforces it.

### What to Keep

- All existing compliance mappings (OWASP / MASVS / NIST / IEC 62443 / SOC 2).
- All production code unchanged.
- THREAT_MODEL.md structure — only the compliance section gains one cross-link row.

### What to Change

- **`docs/compliance/anssi-rust.md`** — NEW (M1 skeleton, M2 filled).
- **`docs/compliance/README.md`** — NEW (M1).
- **`docs/dev-guide/anssi-mapping.md`** — NEW (M2).
- **`THREAT_MODEL.md`** — append cross-link row to the compliance section (M2).
- **`scripts/anssi-mapping-lint.sh`** — NEW (M3).
- **`.github/workflows/ci.yml`** — extend supply-chain job with the lint step (M3).
- **`README.md`** — mention ANSSI compliance in the supply-chain or compliance section (M2).
- **`CHANGELOG.md`** — entry per milestone.

### Global Red Lines

Inherits §9 of v4. Plus:

- No production-code changes.
- No claims of "NIS2 compliance" or "CRA compliance" via this mapping — research says ANSSI is not cited by either.
- No fabricated evidence pointers — every file:line / test / lint must exist at the time of writing.
- No drift — the ANSSI commit hash is stated and frozen until a separate refresh runbook updates it.

---

## 10. Carry-forward from prior retros

(Empty.)

---

## 11–14. BDD / Dependency / Evidence / Self-Review

Inherits §11–14 of v4.

---

## 15–16. Lessons / Completion Templates

Standard v4. Lessons → `docs/slo/lessons/anssi-m<N>.md`; completion → `docs/slo/completion/anssi-m<N>.md`.

---

## 17. Milestone Plan

### Milestone 1 — Bootstrap mapping doc with rule index

**Goal**: Publish `docs/compliance/anssi-rust.md` with all 61 ANSSI rules listed (DENV 8, LIBS 5, LANG 16, MEM 10, FFI 21, UNSAFE 1 per research), the ANSSI commit hash pinned at the top, an empty Status column on every row, and a `docs/compliance/README.md` landing page. No evidence filled yet — that's M2's job.

**Carmack-style reliability goal**: Bounded resources (61 rules — bounded by the pinned commit; resource bound documented in the doc header).

**Important design rule**: The mapping table's column shape is locked in M1 and not re-litigated in M2. Columns: Rule ID (English) | French ID | Family | Rule (English) | Status | Evidence | Notes.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Files allowed to change | `docs/compliance/anssi-rust.md` (NEW), `docs/compliance/README.md` (NEW), `CHANGELOG.md` |
| New files allowed | The two `docs/compliance/` files |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | All existing tests, CI lanes, and docs unchanged. THREAT_MODEL.md untouched in M1 (M2 adds the cross-link). |
| Resource bounds introduced/changed | The mapping document is bounded by the 61 rules in the pinned ANSSI commit. Adding rows requires refreshing the pin in a follow-up runbook. |
| Invariants/assertions required | (1) Every row has a Status column populated (with `unfilled` placeholder allowed in M1; M2 must fix). (2) The ANSSI commit hash matches `84e6ae181712c9ed797aeaf695c9965a13a1d5fa`. (3) Rule count = 61. |
| Debugger / inspection expectation | A reader can scroll the rule index and see all 61 rules with their families. The doc renders correctly in GitHub-flavored Markdown preview. |
| Static analysis gates | All v4 §4.2 gates. (No code changes; lint chain is a smoke check.) |
| Forbidden shortcuts | No "we'll fill in the rest later" without `unfilled` placeholder. No abbreviated rule list — all 61 must appear. No invented rule IDs. |
| Data classification | `Public` |
| Proactive controls in play | `C2` (Frameworks/Libraries — ANSSI as a recognised secure-coding standard). |
| Abuse acceptance scenarios | (no new surface introduced — N/A — this milestone is documentation only. Per v4 SKILL: documentation-only milestones may use `N/A — no new surface introduced` with reason.) |

#### Out of Scope / Must Not Do

- Filling evidence pointers (M2).
- Cross-link from THREAT_MODEL.md (M2).
- The CI lint (M3).
- Any production-code change.

#### Step-by-Step

1. Read research dossier; confirm rule count = 61 and family breakdown.
2. Create `docs/compliance/README.md` introducing the directory.
3. Create `docs/compliance/anssi-rust.md` with the column shape locked, the ANSSI pin in the header, all 61 rule rows populated with `unfilled` Status placeholder.
4. Verify the rule rows are sourced from the ANSSI commit (citation links per row, optional but recommended).
5. CHANGELOG entry.
6. Run formatter + lint (no production changes; quick).
7. Smoke + Self-Review.

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| 61 rules present | happy path | post-M1 doc | count rows in mapping table | exactly 61 |
| family counts match | invariant | post-M1 doc | tally Family column | DENV 8, LIBS 5, LANG 16, MEM 10, FFI 21, UNSAFE 1 |
| ANSSI commit pinned | invariant | post-M1 doc | inspect header | `84e6ae181712c9ed797aeaf695c9965a13a1d5fa` cited |
| no empty Status column | invariant | post-M1 doc | grep for empty Status | every row populated (`unfilled` placeholder allowed in M1) |
| GitHub preview renders | happy path | open the file in a Markdown viewer | inspect | table renders, columns aligned |
| existing docs unchanged | compatibility | THREAT_MODEL.md, README.md | diff against pre-M1 | unchanged |

#### Documentation requirements (M1-specific)

- `docs/compliance/README.md` introduces the directory.
- `docs/compliance/anssi-rust.md` has a header section: "Pinned to ANSSI commit `84e6ae18` (2026-04-07). Refresh requires a separate runbook."
- CHANGELOG entry: "Bootstrap ANSSI Rust compliance mapping doc (61 rules, structured table, pinned to commit `84e6ae18`). Evidence pointers and waivers land in next release."

(Files Allowed, Regression Tests, Compatibility Checklist, E2E, Smoke, Evidence Log, DoD per v4 template.)

---

### Milestone 2 — Fill evidence pointers; document waivers; cross-link from THREAT_MODEL.md

**Goal**: Every ANSSI rule has a real Status (`compliant | partial | waived | N/A`) and either (a) a concrete evidence pointer or (b) a named compensating control. THREAT_MODEL.md compliance section cross-links to the mapping. A consumer-facing dev-guide page explains how to use the mapping.

**Carmack-style reliability goal**: Make invalid states unrepresentable (no `unfilled` Status in M2 output); static analysis (M3 will lint, but M2 produces a doc that *would pass* the M3 lint by hand).

**Important design rule**: Evidence pointers are concrete: `file:line` for code locations, `test_name` for tests, `clippy::lint_name` for lints, `<doc-path>` for docs. Vague evidence like "implemented in the codebase" is rejected.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Files allowed to change | `docs/compliance/anssi-rust.md` (fill evidence column for every row), `docs/dev-guide/anssi-mapping.md` (NEW), `THREAT_MODEL.md` (compliance section: add ANSSI row + cross-link), `README.md` (compliance section reference), `CHANGELOG.md` |
| New files allowed | `docs/dev-guide/anssi-mapping.md` |
| New dependencies allowed | `none` |
| Migration allowed | `no` |
| Compatibility commitments | All existing compliance mappings unchanged in shape. Production code untouched. THREAT_MODEL.md only gains a row + a cross-link sentence; existing rows untouched. |
| Resource bounds introduced/changed | (none new) |
| Invariants/assertions required | (1) No `unfilled` Status remains. (2) Every "compliant" row has a concrete evidence pointer (regex-checkable in M3). (3) Every "waived" row has a "Compensating control: …" line in Notes. (4) THREAT_MODEL.md cross-links exactly once. |
| Debugger / inspection expectation | A future M3 lint can mechanically resolve every evidence pointer to a real artifact. |
| Static analysis gates | All v4 §4.2 gates. The mapping's evidence column is hand-validated against the codebase as of the milestone's commit. |
| Forbidden shortcuts | No vague evidence ("see related code"). No "TODO: clarify later." No claiming compliance for a rule whose enforcement is purely aspirational — partial / waived is honest, compliant-without-evidence is not. |
| Data classification | `Public` |
| Proactive controls in play | `C2` (ANSSI mapping); `C9` (audit-trail evidence). |
| Abuse acceptance scenarios | `tm-anssi-abuse-1`: an auditor cites the mapping; a contributor changes a referenced file/line without updating the mapping → the M3 lint (next milestone) catches the dead pointer. M2 itself is documentation only, so this is a forward-looking abuse case the M3 lint addresses. |

#### Out of Scope / Must Not Do

- The CI lint (M3).
- Any production-code change.
- Adding rules beyond the 61 (refresh runbook, post-this).

#### Step-by-Step

1. Read M1 lessons.
2. For each rule, classify: compliant / partial / waived / N/A. For compliant rows, identify the evidence pointer (file:line, test, lint, doc). For waived, name the compensating control. For N/A, state why.
3. Cross-link from THREAT_MODEL.md compliance section.
4. Write `docs/dev-guide/anssi-mapping.md` describing the doc's structure and how to consume it.
5. Update README to mention ANSSI compliance.
6. CHANGELOG entry.
7. Smoke + Self-Review.

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| no `unfilled` rows | invariant | post-M2 doc | grep for `unfilled` in the Status column | no matches |
| every compliant row has an evidence pointer | invariant | post-M2 doc | regex-scan rows where Status=compliant | every Evidence cell non-empty and resolves to a real file/test/lint |
| every waived row has a compensating control | invariant | post-M2 doc | grep "Compensating control:" near waived rows | exactly one named control per waived row |
| THREAT_MODEL.md cross-link present | compatibility | THREAT_MODEL.md | search for `anssi-rust.md` link | exactly one link in the compliance section |
| existing compliance mappings unchanged | compatibility | THREAT_MODEL.md | diff against pre-M2 minus the new row | other rows unchanged |
| dev-guide explains use | happy path | `docs/dev-guide/anssi-mapping.md` | read | sections: pin, structure, how to use, leverage framing (state-of-the-art / IEC 62443) |
| no NIS2/CRA "compliance" claim | abuse case (`tm-anssi-abuse-2`) | the mapping + dev-guide | grep for "NIS2 compliant" or "CRA compliant" | no matches; instead language reads "state-of-the-art evidence" or "audit support" |

#### Documentation requirements (M2-specific)

- `docs/dev-guide/anssi-mapping.md` complete: pinned commit, table structure, Status enum, Evidence convention, Documented Deviations, leverage framing.
- THREAT_MODEL.md compliance section: one row added cross-linking to the mapping.
- README compliance/supply-chain section: one-line mention.
- CHANGELOG: "Published per-rule ANSSI Rust compliance mapping (61 rules, evidence-pointer-backed). EU consumers can cite the mapping in procurement / IEC 62443 audits."

(Files Allowed, Regression, Compatibility, E2E, Smoke, Evidence Log, DoD per v4.)

---

### Milestone 3 — CI lint catching dead evidence pointers

**Goal**: `scripts/anssi-mapping-lint.sh` parses `docs/compliance/anssi-rust.md`, validates that every evidence pointer resolves (file:line exists; test name exists in `cargo test --list`; clippy lint name is recognised), and runs in the supply-chain CI job. Failure means a real or aspirational regression — block the build.

**Carmack-style reliability goal**: Static analysis is mandatory (the new lint *is* the static analysis); make invalid states unrepresentable (a stale pointer becomes a build failure, not a hidden drift).

**Important design rule**: The lint is conservative — it accepts a row's evidence as valid if any pointer in the cell resolves; it fails if all pointers in the cell are stale. False positives are worse than false negatives in M3 because the lint is gating.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Files allowed to change | `scripts/anssi-mapping-lint.sh` (NEW), `.github/workflows/ci.yml` (extend supply-chain job with lint step), `docs/dev-guide/anssi-mapping.md` (add "Lint behaviour" section), `CHANGELOG.md` |
| New files allowed | `scripts/anssi-mapping-lint.sh` |
| New dependencies allowed | `ripgrep` (already on most CI images; install via `apt-get install -y ripgrep` in the CI step if missing). No Rust deps. |
| Migration allowed | `no` |
| Compatibility commitments | Existing supply-chain steps (`cargo audit`, `cargo deny`, `cargo vet`) unchanged. CI runtime cap stays within current bound (this lint is fast). |
| Resource bounds introduced/changed | Lint runtime cap = 60 seconds (parses ~61 rows, runs `cargo test --list` once, scans for clippy lint names in `cargo clippy -- --help` output). |
| Invariants/assertions required | (1) Lint script exits 0 if every "compliant" row's Evidence resolves; non-zero otherwise. (2) Lint output names the failing rule(s) and the unresolved pointer(s). (3) Lint runs in CI on every PR. |
| Debugger / inspection expectation | `bash -x scripts/anssi-mapping-lint.sh` shows step-by-step pointer resolution. Clear error messages on failure. |
| Static analysis gates | All v4 §4.2 gates plus the new lint in CI. |
| Forbidden shortcuts | No "false-positive bypass" via blanket pattern matching. No `set +e` to silence failures. No `|| true` on the lint step. |
| Data classification | `Public` |
| Proactive controls in play | `C2` (Frameworks/Libraries — automated lint), `C9` (audit evidence — CI job logs). |
| Abuse acceptance scenarios | `tm-anssi-abuse-1` (carried from M2): a contributor refactors a referenced file/line without updating the mapping → lint catches at CI; PR cannot merge until either the mapping is updated or the rule is re-classified. `tm-anssi-abuse-3`: a contributor disables the lint step in `ci.yml` → the change is visible in the PR diff and reviewed normally. |

#### Out of Scope / Must Not Do

- Promoting the lint to verify partial / waived rows beyond their compensating-control pointer. (Initial scope: compliant rows + waived-row-control-name presence; partial and N/A pass through.)
- Refreshing the ANSSI commit pin (post-this runbook).

#### Step-by-Step

1. Read M2 lessons.
2. Write the Bash script: parse the mapping; for each compliant row, attempt to resolve the evidence pointer; report errors.
3. Local test: run against current `anssi-rust.md`; confirm zero failures (M2 should have left no dead pointers).
4. Mutation test: rename a referenced file; run lint; confirm it fails with a clear message; restore.
5. Wire into `.github/workflows/ci.yml` supply-chain job.
6. Update dev-guide with "Lint behaviour" section.
7. CHANGELOG.
8. Run formatter / lint chain; smoke; Self-Review.

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| lint passes on current mapping | happy path | post-M2 mapping; current codebase | run `scripts/anssi-mapping-lint.sh` | exit 0; no errors |
| stale file pointer caught | abuse case (`tm-anssi-abuse-1`) | mutate a referenced file path | run lint | exit non-zero; error names the rule and the dead pointer |
| stale test name caught | abuse case | rename a referenced test | run lint | exit non-zero |
| invalid lint name caught | invalid input | mapping references `clippy::nonexistent_lint` | run lint | exit non-zero |
| CI step disabled visibility | abuse case (`tm-anssi-abuse-3`) | ci.yml diff drops the step | reviewer reads diff | change visible; not silently bypassed |
| existing supply-chain steps unchanged | compatibility | `cargo audit` / `cargo deny` / `cargo vet` | CI runs | each still passes per existing policy |
| lint runtime within cap | resource bound | run on PR | check timing | < 60 seconds |

#### Documentation requirements (M3-specific)

- `docs/dev-guide/anssi-mapping.md` final form: includes "Lint behaviour" section.
- CHANGELOG: "ANSSI compliance mapping is now CI-checked: dead evidence pointers fail the build. Per-rule auditors can rely on the mapping being current as of any green commit."

(Files Allowed, Regression, Compatibility, E2E, Smoke, Evidence Log, DoD per v4.)

---

## 18. Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 1 | (no change) | (no change) | — | `docs/compliance/anssi-rust.md` (NEW skeleton), `docs/compliance/README.md` (NEW), CHANGELOG |
| 2 | (no change) | Mention ANSSI compliance in compliance section | — | `docs/dev-guide/anssi-mapping.md` (NEW), THREAT_MODEL.md cross-link, mapping doc filled, CHANGELOG |
| 3 | (no change) | (no change) | — | dev-guide "Lint behaviour" section added, CHANGELOG |

---

## 19. Optional Fast-Fail Review Prompt for Agents

> Restate the milestone goal, allowed files, forbidden changes, compatibility, dependencies, regression tests, lint shape (M3), and Definition of Done. Cite the research dossier for the rule-family count and the ANSSI commit pin.

---

## 20. Source Basis

This runbook is a v4 instance authored against [`docs/slo/templates/runbook-template_v_4_template.md`](../templates/runbook-template_v_4_template.md). Research basis: [`docs/slo/research/anssi-rust-compliance/dossier.md`](../research/anssi-rust-compliance/dossier.md) (43 sources, `incomplete:false`; pinned ANSSI commit `84e6ae181712c9ed797aeaf695c9965a13a1d5fa` 2026-04-07; 61 rules; NIS2 + CRA do *not* cite ANSSI directly — leverage is "state-of-the-art evidence in French / IEC 62443-4-1 SD-3 audits"). Idea basis: [`docs/slo/idea/anssi-rust-compliance.md`](../idea/anssi-rust-compliance.md).

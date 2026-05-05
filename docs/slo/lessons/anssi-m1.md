# Lessons Learned — anssi Milestone 1

## What changed
- Created `docs/compliance/` directory with a `README.md` landing page for per-framework compliance mappings.
- Created `docs/compliance/anssi-rust.md` with all 61 ANSSI rules at the pinned commit `84e6ae18`, organized by family (DENV 8, LIBS 5, LANG 16, MEM 10, FFI 21, UNSAFE 1). Status column carries the `unfilled` placeholder for M2.
- Updated runbook tracker: M1 done.

## Design decisions and why
- **Rule data sourced directly from ANSSI repo at the pinned commit** — fetched the source markdown files from `raw.githubusercontent.com/ANSSI-FR/rust-guide/84e6ae18/src/en/...` and parsed `<div class="reco" id="..." type="..." title="...">` blocks. This guarantees rule IDs and titles match the upstream source byte-for-byte.
- **Pin by commit SHA, not by tag** — the only Git tag (`v1.0`) is from 2020-06-15 and predates most of the current rule set. The site banner reads "Secure Rust Guidelines (unstable)". Pinning by SHA is the only honest choice.
- **Six family sections in the rule index** — matches the dossier's family-count breakdown. Each section has its own H3 + table, easier to navigate than a single 61-row table.
- **`unfilled` placeholder is explicit, not blank** — every row's Status is filled with `unfilled` rather than left empty. Two reasons: (1) M2 must replace each `unfilled` to be done, so a grep count is the success metric; (2) blank cells render inconsistently in some Markdown viewers.
- **English IDs only (for now)** — research confirmed English and French slugs are identical at this commit, so the parallel-French-ID column would be redundant. If a future ANSSI revision changes the slugs, the column can be added.
- **Type column carries `Rule | Recommendation` per ANSSI's own taxonomy** — preserves the source distinction, which an auditor may care about (rules are stricter than recommendations).
- **Status enum is fixed at five values: `compliant | partial | waived | N/A | unfilled`** — `unfilled` is M1-only; M2 must reduce this enum to four. This is documented in the doc itself.
- **Compliance directory layout** — `docs/compliance/` separates this from `docs/dev-guide/` (consumer-facing how-tos) and `docs/slo/` (runbook artifacts). Future framework mappings (BSI, NCSC, etc.) follow the same shape.

## Assumptions verified
- The ANSSI repo at the pinned commit has exactly 61 rules across the 6 families. Verified by per-file extraction.
- English and French rule slugs are identical at this commit (resolves an open question from the idea doc).
- The `<div class="reco">` HTML pattern in the source markdown reliably encodes the rule ID, type, and title. Verified across all 9 source files.

## Assumptions still unresolved
- Whether ANSSI will retire the "unstable" site banner before SunLit's first 1.0 release. If they do, the pin format may change (e.g., adopting semantic version tags). Not blocking; revisit at runbook refresh.
- Whether any of the 61 rules will be split or merged in a future revision. Refresh procedure is documented in the mapping doc.

## Mistakes made
- None material in M1. The fetch worked first try; the count matched first try.

## Root causes
- N/A.

## What was harder than expected
- Nothing. The dossier had family counts and source files; the actual rule IDs were one curl + grep away.

## Invariants/assertions added or strengthened
- **Documentation invariant**: the mapping doc has exactly 61 rows; the family counts equal 8 / 5 / 16 / 10 / 21 / 1. M3 will encode this as a CI-checkable assertion if the doc shape changes.
- **Pin invariant**: the doc cites the ANSSI commit SHA in two places (header + family-summary table); both must agree. M3's lint can check this.

## Resource bounds established or verified
- Mapping doc: 61 rows. Bounded by the ANSSI commit pin.
- Two new files; ~12 KB combined.

## Debugging / inspection notes
- The fetch step printed rule IDs and titles per file — a good record to compare against the rendered ANSSI site if a future refresh changes any rule. The transcript in this milestone's commit message is the audit trail.

## Naming conventions established
- `docs/compliance/<framework-slug>.md` — per-framework mapping document.
- `docs/compliance/README.md` — directory index.
- `unfilled` is the M1-only Status placeholder; M2 must eliminate.
- Rule IDs use English slugs (matching upstream) — never localised.

## Test patterns that worked well
- Raw GitHub content fetch + grep extraction is the right pattern for upstream-derived documentation. It's reproducible: future-self at the same pin will get the same rules.

## Missing tests that should exist now
- M3's `scripts/anssi-mapping-lint.sh` will introduce the test (verify evidence pointers + commit pin + row count).

## Rules for the next milestone (anssi M2 — fill evidence pointers)
- Every row's Status must move from `unfilled` to one of `compliant | partial | waived | N/A`.
- `compliant` rows must have a concrete evidence pointer (file:line, test name, or `clippy::lint_name`).
- `waived` rows must name the compensating control in Notes.
- The "Documented Deviations" section is populated for every `waived` row.
- THREAT_MODEL.md cross-link added.
- Honest leverage framing: no "NIS2 compliance" or "CRA compliance" claims anywhere.
- Cross-reference `docs/dev-guide/unsafe-budget.md` for evidence on `LANG-UNSAFE`, `LANG-UNSAFE-ENCP`, `UNSAFE-NOUB`.

## Template improvements suggested
- v4 runbook M1 BDD scenarios were specific enough to drive execution. The "61 rules" invariant could be a CI test from M3 onwards; mark this as a follow-up.

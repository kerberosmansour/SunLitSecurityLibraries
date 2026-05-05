# Completion Summary — anssi Milestone 1

## Goal completed
Bootstrapped the per-rule ANSSI Rust Secure Coding Guidelines compliance mapping. The document `docs/compliance/anssi-rust.md` lists all 61 rules from the pinned ANSSI commit (`84e6ae18`, 2026-04-07), organized by family (DENV 8, LIBS 5, LANG 16, MEM 10, FFI 21, UNSAFE 1). Status column carries the `unfilled` M1 placeholder for every row; M2 fills evidence pointers and named compensating controls.

## Files changed
- `docs/compliance/README.md` — NEW, directory index.
- `docs/compliance/anssi-rust.md` — NEW, 61-row mapping document with family sections, pinned ANSSI commit, status enum, refresh procedure.
- `docs/slo/lessons/anssi-m1.md` — NEW.
- `docs/slo/completion/anssi-m1.md` — NEW (this file).
- `docs/slo/future/RUNBOOK-anssi-rust-compliance.md` — M1 marked done.

## Tests added
- N/A in unit-test sense; M3 introduces the CI lint.

## Runtime validations added
- Mapping doc verified by inspection: 61 rows, family counts 8 / 5 / 16 / 10 / 21 / 1, ANSSI commit pin cited in 5 places (header + summary table + README + footer + refresh procedure).

## Static analysis and formatter evidence
- `cargo fmt --all -- --check` — clean (no Rust changes).
- `cargo test --workspace` — 22 pass (existing tests unchanged).

## Compatibility checks performed
- THREAT_MODEL.md and other compliance mappings unchanged.
- No production code modified.

## Invariants/assertions added
- Mapping doc has exactly 61 rows.
- Family counts equal 8 / 5 / 16 / 10 / 21 / 1.
- ANSSI commit pin matches `84e6ae181712c9ed797aeaf695c9965a13a1d5fa`.
- Every row has a Status (`unfilled` placeholder permitted in M1; M2 must replace).

## Resource bounds added or verified
- Mapping doc: 61 rules, bounded by the ANSSI commit pin.
- Two new files; ~12 KB.

## Documentation updated
- `docs/compliance/README.md`, `docs/compliance/anssi-rust.md` (NEW).
- `docs/slo/future/RUNBOOK-anssi-rust-compliance.md` tracker.

## .gitignore changes
- None required.

## Test artifact cleanup verified
- `git status` clean of any test artifacts.

## Deferred follow-ups
- M2: replace every `unfilled` Status with a concrete classification + evidence.
- M3: CI lint script to catch dead evidence pointers + drifted commit pin.
- A future "ANSSI guide refresh" runbook for the next ANSSI commit bump.

## Known non-blocking limitations
- M1 deliberately leaves Status columns at `unfilled` — this is a placeholder, not the final state. M2 closes that gap.
- The mapping covers only the English rendering of the ANSSI guide; the French rendering's slug parity at this commit makes a parallel-French-ID column redundant for now (documented).

# Lessons Learned — anssi Milestone 2

## What changed

- Replaced all `unfilled` placeholders in `docs/compliance/anssi-rust.md` with final M2 classifications.
- Added concrete evidence pointers and notes for every ANSSI row.
- Added two documented deviations: `DENV-AUTOFIX` and `LIBS-OUTDATED`.
- Cross-linked the ANSSI mapping from `THREAT_MODEL.md` and README.
- Added `docs/dev-guide/anssi-mapping.md`.

## Classification outcome

| Status | Count |
|---|---:|
| `compliant` | 27 |
| `partial` | 7 |
| `waived` | 2 |
| `N/A` | 25 |

The distribution came from reading the pinned upstream ANSSI rule definitions and classifying against the current workspace. FFI accounts for most `N/A` rows because SunLit exposes Rust crate APIs only and enforces `#![forbid(unsafe_code)]` across workspace crates.

## Decisions and why

- **Do not over-claim panic and arithmetic coverage** — panic, unwrap/expect, indexing, and arithmetic restriction lints are documented but not globally enforced, so those rows are `partial`.
- **Waive `cargo-outdated` rather than pretend it runs** — Dependabot already provides scheduled dependency freshness PRs. That is a legitimate compensating control, but it is not the same tool as the ANSSI row names.
- **Make FFI `N/A`, not compliant** — there is no FFI surface to assess. The relevant evidence is the workspace no-unsafe invariant and source scan.
- **Keep evidence pointers simple** — most compliant rows cite a file:line, a CI step, or a clippy lint name that the M3 script can parse.

## Mistakes made

- A zsh loop initially used `path` as the variable name while fetching upstream ANSSI files. In zsh that mutates the command search path. Renaming the variable to `rel` fixed the fetch.

## Invariants strengthened

- No `unfilled` Status remains in the ANSSI mapping.
- Every waived row starts its Notes cell with `Compensating control:`.
- THREAT_MODEL.md links to the mapping exactly once.
- The leverage framing stays honest: ANSSI is state-of-the-art evidence and IEC 62443-4-1 SD-3 support, not a direct NIS2/CRA claim.

## Follow-ups

- M3 should land the lint script and CI step already planned in the runbook.
- A future hardening runbook can consider enabling selected Clippy restriction lints (`panic`, `unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects`, `mem_forget`) if the team wants more rows to move from `partial` to `compliant`.

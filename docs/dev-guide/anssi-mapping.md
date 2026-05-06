# ANSSI Rust Mapping Guide

## Pinned Commit

The mapping is pinned to ANSSI-FR `rust-guide` commit `84e6ae181712c9ed797aeaf695c9965a13a1d5fa`, dated 2026-04-07. The rendered ANSSI guide is labelled unstable, so the SunLit mapping is tied to that commit hash until a deliberate refresh runbook changes it.

## Mapping Structure

The mapping lives at [`docs/compliance/anssi-rust.md`](../compliance/anssi-rust.md). It is grouped by ANSSI rule family:

| Family | Scope |
|---|---|
| DENV | Toolchain, Cargo, formatter, and linter hygiene |
| LIBS | Dependency vetting, advisories, freshness, and unsafe dependency visibility |
| LANG | Rust language constructs such as arithmetic, panic use, comparisons, `Drop`, and unsafe |
| MEM | Memory-management rules, mostly reduced by the workspace `forbid(unsafe_code)` posture |
| FFI | Foreign-function-interface rules; currently not applicable because no SunLit crate exposes FFI |
| UNSAFE | Umbrella undefined-behaviour posture |

Each rule row has the columns `Rule`, `Type`, `Title`, `Status`, `Evidence`, and `Notes`.

| Status | Meaning |
|---|---|
| `compliant` | The workspace satisfies the rule today and the Evidence cell points to a concrete artifact. |
| `partial` | The rule is partly covered, but the Notes cell explains the caveat. |
| `waived` | The rule is deliberately not followed exactly; Notes start with a named compensating control. |
| `N/A` | The rule does not apply to this workspace, with the reason stated in Notes. |

## How To Consume

Start with the family summary, then filter to the family relevant to the audit question. For a dependency review, inspect LIBS. For unsafe or FFI review, inspect LANG, MEM, FFI, and UNSAFE. Follow the Evidence pointer in each row to the file, CI step, lint name, test, or supporting guide.

Auditors should treat `compliant` rows as directly evidenced, `partial` rows as caveated controls requiring review, `waived` rows as accepted deviations with compensating controls, and `N/A` rows as out-of-scope for the current Rust crate surface.

## Documented Deviations

| Rule | Compensating control |
|---|---|
| `DENV-AUTOFIX` | Reviewer-owned PR review; no automatic fix tool is run in CI, so any generated change is reviewed as an ordinary diff. |
| `LIBS-OUTDATED` | Weekly Dependabot Cargo update PRs replace a dedicated `cargo-outdated` gate; audit, deny, and vet still run on every PR. |

## Refresh Cadence

Do not bump the ANSSI pin opportunistically. Open a new runbook when a refresh is needed, compare the pinned commit to the new upstream commit, update the rule count and row titles, reclassify changed rules, and record the change in `CHANGELOG.md`.

## Honest Leverage Framing

This mapping is state-of-the-art secure-coding evidence for French-market procurement and IEC 62443-4-1 SD-3 audit support. NIS2 and the EU Cyber Resilience Act do not directly cite the ANSSI Rust guide, so the mapping should not be presented as direct regulatory conformance.

## Lint Behaviour

`scripts/anssi-mapping-lint.sh` checks the pinned commit, the 61-row count, non-empty Status cells, and resolvable Evidence pointers for `compliant` rows. Treat the script as the source of truth for exact validation rules.

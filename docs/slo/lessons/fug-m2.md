# Lessons Learned — fug Milestone 2

## What changed
- Added `cargo-geiger` (pinned `0.13.0`) to the supply-chain CI lane (`.github/workflows/ci.yml`) as an advisory step (`continue-on-error: true`, `timeout-minutes: 10`).
- Added an `actions/upload-artifact` step that uploads `output/cargo-geiger.json` with 30-day retention.
- Mirrored the invocation in `scripts/audit.sh` and `scripts/audit.ps1` so local runs match CI.
- Updated `docs/dev-guide/unsafe-budget.md` with the locked invocation, the measured baseline, and the threshold semantics.
- Updated `README.md` supply-chain bullet list to mention the geiger lane.
- Updated `CHANGELOG.md` Unreleased.
- Marked M2 done in the runbook tracker.

## Design decisions and why
- **Root package = `secure_reference_service`** — `cargo-geiger` requires a single root package (it cannot consume a virtual manifest, which is what SunLit's `Cargo.toml` is). The reference service depends on every library crate, so its dep graph is a superset of any single library's dep graph. It also matches what a downstream integrator's audit would look like.
- **Pin geiger to `0.13.0`** — research dossier called out cargo-geiger as "active but partial maintenance"; pinning prevents drift caused by version bumps that change output format or dep set. A version bump is a deliberate runbook change.
- **`--all-features` for the official number** — worst-case across every published feature combination of the reference service. Consumers with narrower feature sets see a smaller footprint.
- **Advisory, not blocking** — research recommended advisory until ≥1 release cycle of stable signal. `continue-on-error: true` makes the step yellow on the PR rather than failing the merge.
- **Threshold = baseline + 10 % headroom** — informational delta detector, not a gate. The 10 % was chosen to absorb noise from common ecosystem dep updates (e.g., `proc-macro2`, `serde`, `tokio` patch versions) without false positives.
- **Per-crate iteration deferred** — the runbook envisioned `--workspace`; cargo-geiger does not support that. Per-crate iteration would give a true workspace upper bound but adds CI runtime. The reference-service approach is the pragmatic single-run choice; per-crate iteration is a documented future enhancement.
- **Artifact is the source of truth** — the published number in the dev-guide is a release-cycle snapshot; the CI artifact is the canonical per-PR value. This keeps the doc from drifting with every dep update.

## Assumptions verified
- `cargo-geiger 0.13.0` installs and runs against `secure_reference_service` end-to-end. Output produced 331 warnings (per-dep-without-forbid notices); these are informational.
- All 14 SunLit crates show `:)` (forbid declared, no unsafe used). The transitive unsafe is entirely in deps.
- Top contributors to the unsafe count: `tokio`, `time`, `serde_json`, `tracing-subscriber`, `hyper` — all well-audited primitives.

## Assumptions still unresolved
- Whether the reference-service number underestimates the workspace upper bound by enough to matter. A per-crate iteration would clarify; deferred to a future runbook.
- Whether `cargo-geiger 0.13.0` will continue to work as toolchains evolve through 2026. The pin makes drift visible; renewal is a deliberate decision.

## Mistakes made
- Initial drafts of the runbook + CI step used `--workspace` flag, which `cargo-geiger` does not accept (virtual-manifest limitation). Caught at first local run.
- Initial CI step used a different `actions/upload-artifact` SHA than the one already in the repo. Aligned to the existing pin (`ea165f8d…`) for consistency.

## Root causes
- The runbook's tooling assumption was generic (`cargo geiger --workspace`); the tool's actual flag set is more restrictive. Lesson: validate tool invocations against the actual tool, not the conceptual model, before locking the runbook.

## What was harder than expected
- Geiger requires a non-virtual root and the workspace is a virtual manifest. The fix (pick a representative root crate) is small but the choice has audit implications — documented explicitly so a future contributor doesn't second-guess.

## Invariants/assertions added or strengthened
- **Build-time invariant** (advisory): every PR's geiger artifact is an upper bound on the transitive `unsafe` exposure of a downstream consumer that uses every published feature of the reference service. Deviation above the threshold triggers a reviewer action (artifact diff).

## Resource bounds established or verified
- CI step timeout: 10 minutes (per research recommendation; geiger runs in ~3 min on a warm cache locally).
- Artifact retention: 30 days. Older runs are GC'd by GitHub Actions.

## Debugging / inspection notes
- Mutation paths to consider for future readers: (a) introduce a dep that has unsafe; geiger number rises; CI artifact diff shows the new dep. (b) Toolchain bumps `proc-macro2` patch; geiger number ticks +/- a small amount; absorbed by the 10 % threshold headroom.

## Naming conventions established
- `output/cargo-geiger.json` is the canonical path for the JSON artifact, both in CI and local audit scripts.
- The dev-guide section title is "Transitive `cargo-geiger` number" (not "Geiger metric"); chosen for explicit, non-jargon clarity.

## Test patterns that worked well
- Running `cargo geiger` locally before wiring the CI step caught the virtual-manifest limitation. Always test the tool invocation locally before encoding it in CI.

## Missing tests that should exist now
- A future test could parse `output/cargo-geiger.json` and assert `total_unsafe_count <= threshold`. Deferred to the future "promote to blocking gate" runbook.

## Rules for the next milestone (anssi-rust-compliance M1)
- Doc-only milestone; no production-code change.
- Pin the ANSSI guide commit hash exactly: `84e6ae181712c9ed797aeaf695c9965a13a1d5fa` (2026-04-07).
- All 61 rules listed; no abbreviated subset.
- Every Status column populated (`unfilled` placeholder allowed in M1; M2 fixes).

## Template improvements suggested
- The v4 runbook M2 BDD section assumed `cargo geiger --workspace`; for future runbooks that reference tool invocations, validate the tool's actual flag set before locking the BDD scenarios. The runbook author (me) should have run the tool first.

# Completion Summary — fug Milestone 2

## Goal completed
`cargo-geiger` (pinned `0.13.0`) runs as an advisory step on every PR via the supply-chain CI lane, uploading `output/cargo-geiger.json` as a 30-day-retention artifact. The published baseline (root = `secure_reference_service`, `--all-features`) is **22 636 transitive unsafe expressions used / 48 192 available**. SunLit crates contribute zero. The threshold (baseline + 10 % headroom) and reviewer-action procedure are documented in `docs/dev-guide/unsafe-budget.md`. Local parity via `bash scripts/audit.sh` and `pwsh scripts/audit.ps1`.

## Files changed
- `.github/workflows/ci.yml` — supply-chain job now installs `cargo-geiger 0.13.0`, runs it (advisory, 10-min cap, root = `secure_reference_service`), and uploads the JSON artifact.
- `scripts/audit.sh` — Step 5 added; mirrors CI invocation.
- `scripts/audit.ps1` — same, in PowerShell.
- `docs/dev-guide/unsafe-budget.md` — completed M2 section: locked invocation, measured baseline, threshold, reviewer-action procedure.
- `README.md` — supply-chain bullets updated with the geiger lane.
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/lessons/fug-m2.md` — NEW, lessons-learned.
- `docs/slo/completion/fug-m2.md` — NEW (this file).
- `docs/slo/future/RUNBOOK-forbid-unsafe-and-geiger.md` — M2 marked done; runbook complete.

## Tests added
- N/A in unit-test sense; the cargo-geiger step itself is the test/gate.

## Runtime validations added
- The CI step exercises the geiger invocation on every PR.

## Static analysis and formatter evidence
- Local geiger run produced the recorded baseline.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo audit && cargo deny check && cargo vet` — all green.

## Compatibility checks performed
- Existing supply-chain steps (`cargo audit`, `cargo deny`, `cargo vet`, OSV Scanner) unchanged in shape and policy.
- Existing CI workflows untouched.
- All workspace tests continue to pass.
- The geiger step is `continue-on-error: true`; failures do not block PR merge.

## Invariants/assertions added
- **Advisory build-time invariant**: every PR carries a geiger JSON artifact reflecting the transitive `unsafe` upper bound for a downstream consumer using every reference-service feature. Reviewer-action procedure defined for above-threshold deltas.

## Resource bounds added or verified
- CI step timeout: 10 minutes.
- Artifact retention: 30 days.
- Pinned tool version: `cargo-geiger 0.13.0`.

## Documentation updated
- `docs/dev-guide/unsafe-budget.md` — completed.
- `README.md` — supply-chain bullets.
- `CHANGELOG.md` — Unreleased entry.

## .gitignore changes
- None required. `output/` is already ignored.

## Test artifact cleanup verified
- `git status` clean of test outputs after local geiger run.

## Deferred follow-ups
- Per-crate geiger iteration to bound the absolute workspace worst case (vs. the reference-service-rooted upper bound). Deferred — runtime cost in CI, marginal information gain.
- Promotion of geiger to a blocking CI gate. Deferred — separate runbook after ≥1 release cycle of stable signal.
- A small Rust integration test that parses `cargo-geiger.json` and asserts `<= threshold`. Lands with the promotion runbook.

## Known non-blocking limitations
- Cargo-geiger `0.13.0` is volunteer-maintained at partial cadence. The pinned version isolates SunLit from upstream churn; a future bump is a deliberate runbook change.
- The reference-service number is an upper bound for downstream-consumer-style audits; consumers using only one library see less.

# Completion Summary — pqd Milestone 4

## Goal completed
The `fips × pq` interaction is documented honestly. `pq::fips_status()` returns `Some("pending_cmvp")` on `pq`-enabled builds (no CMVP cert covers ML-KEM-768 as of 2026-05). A CI lint blocks any regression of the documentation posture. The `pq-readiness-secure-data` runbook is now complete (M1-M4 done, subject to PR merge).

## Files changed
- `crates/secure_data/src/pq/mod.rs` — `fips_status()`.
- `scripts/lint-fips-pq-claims.sh` (NEW; chmod +x).
- `.github/workflows/ci.yml` — supply-chain step.
- `docs/dev-guide/secure-data.md` — `fips × pq` section + audit-signal docs.
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/lessons/pqd-m4.md`, `docs/slo/completion/pqd-m4.md` (NEW).
- Runbook tracker — M4 done.

## Tests added
- `pq::fips_status()` is exercised by the rustdoc example.
- The CI lint itself is the test; runs on every PR.

## Static analysis and formatter evidence
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo test -p secure_data` — 27 pass; with `--features pq` — 27 pass.
- `bash scripts/lint-fips-pq-claims.sh` — clean.

## Compatibility checks performed
- Existing `secure_data` tests pass.
- No production code change beyond the new free function.
- No wire-format change.

## Documentation updated
- `docs/dev-guide/secure-data.md` (extended PQ Readiness section).
- CHANGELOG.

## Deferred follow-ups
- A future runbook adding a `pq-aws-lc` feature when CMVP-validated ML-KEM is available.
- M2 (#8): hybrid KEM impl — the PQ runbook's heaviest milestone.

## Known non-blocking limitations
- `fips_status()` is a build-time constant. A future runtime-loadable variant could query a CMVP cert ID at startup; not in scope for M4.

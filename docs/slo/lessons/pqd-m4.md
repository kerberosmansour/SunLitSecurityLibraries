# Lessons Learned — pqd Milestone 4

## What changed
- `crates/secure_data/src/pq/mod.rs` — added `fips_status() -> Option<&'static str>`.
- `scripts/lint-fips-pq-claims.sh` (NEW) — CI lint blocking forbidden FIPS-validated-PQ phrasing in docs/code.
- `.github/workflows/ci.yml` — supply-chain job runs the lint after OSV Scanner.
- `docs/dev-guide/secure-data.md` — extended PQ Readiness section with the `fips × pq` interaction discussion, the runtime audit-signal, and the promotion-criteria.
- `CHANGELOG.md` — Unreleased entry.
- Runbook tracker — M4 done.

## Design decisions and why
- **`fips_status()` returns `Option<&'static str>` rather than a typed enum.** The returned string is the audit signal — auditors grep production binaries for `"pending_cmvp"`. A typed enum would not appear as a literal in the binary. `&'static str` is exactly the surface auditors need.
- **Lint regex matches case-insensitive variants.** Catches "FIPS validated PQ", "PQ FIPS validated", "FIPS-validated post-quantum", and similar reorderings.
- **Lint excludes `docs/slo/`.** The migration plan and research dossier explicitly discuss what is *not* yet validated, using the negation framing "validation pending CMVP". The lint targets affirmative claims.
- **Dev-guide rephrasing.** First draft contained the literal forbidden strings inside quotes-as-examples; the lint correctly fired. Reworded to refer to "the script for the exact forbidden patterns" without quoting them.
- **No `pq_fips_status` field on `EnvelopeEncrypted`.** A free function `pq::fips_status()` keeps the wire format unchanged. Auditors who want a per-envelope label can construct one themselves at the call site.

## Assumptions verified
- The lint catches its own forbidden patterns (verified by initial false-positive on the dev-guide).
- `cfg`-gated `fips_status()` returns `None` on non-pq builds and `Some("pending_cmvp")` on pq builds.
- All 4 milestones of the pq-readiness runbook are now landed (subject to PR merge).

## Mistakes made
- First-pass dev-guide quoted the forbidden strings in regular text; the lint correctly fired. The lesson: when documenting forbidden phrasings, refer to the lint script for the patterns rather than quoting the patterns directly.

## Invariants/assertions added or strengthened
- **Documentation invariant**: no forbidden FIPS-validated-PQ claim appears in `README`, `CHANGELOG`, `docs/dev-guide/`, `docs/compliance/`, or `crates/`. Enforced by `scripts/lint-fips-pq-claims.sh` in the supply-chain CI job.
- **Runtime invariant**: `pq::fips_status()` returns `Some("pending_cmvp")` whenever `--features pq` is enabled. Auditors can grep production binaries for the literal.

## Resource bounds established or verified
- Lint runtime: <1 second on the workspace.
- `fips_status()` overhead: zero (compile-time constant).

## Naming conventions established
- `<crate>::<module>::status() -> Option<&'static str>` for build-posture queries.
- Honest-labelling lint scripts: `scripts/lint-<topic>.sh`.

## Rules for the next milestone (any subsequent FIPS work)
- Promote `pq_fips_status` to `Some("validated")` only after all four criteria in the dev-guide §"Promotion criteria" are met.
- A new feature flag (`pq-aws-lc` or similar) selects the validated implementation.
- The lint script's allowed-phrase comment block must list every alternative phrasing of the validation status to keep the gate honest.

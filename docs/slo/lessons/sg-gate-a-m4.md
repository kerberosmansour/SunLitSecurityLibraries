# Lessons Learned — sg-gate-a Milestone 4

## What changed
- `secure_identity` gained `boot::assert_no_dev_identity_in_production` (+ `ProductionModeViolation` error). Re-exported from `lib.rs`.
- `secure_authz::testing::assert_every_route_has_policy` (+ `RouteDescriptor`, `PolicyFixture`, `UnmappedRoute`) added as a dedicated `testing` module (separate from existing `testkit` which holds fixtures).
- `.github/workflows/ci.yml` gained two new jobs: `feature-matrix` (3 crates × 4 feature sets = 12 combos per PR) and `rustdoc-warnings` (treats rustdoc warnings as errors).
- `README.md` gained explicit License section, dev-guide index, and supply-chain-policy pointer.
- `deny.toml` gained a header comment explaining it's the canonical downstream policy.
- `docs/dev-guide/README.md` (index) and `docs/dev-guide/production-checklist.md` added.
- Two new examples: `secure_identity/examples/production_boot.rs` and `secure_authz/examples/route_coverage.rs`.

## Design decisions and why
- **A4 takes `has_dev_identity_source: bool`** rather than a validator handle. Rationale: detection-of-dev-source logic varies per service (some use `cfg!(feature = "dev")`, others register explicit authenticators, others use env vars). Putting detection inside `secure_identity` would force a narrow API; a bool keeps the helper tiny while carrying the env-string check it's actually about.
- **A5 creates a NEW `testing` module instead of extending `testkit`.** `testkit` holds one-shot mocks (MockAuthorizer, fixture subjects). `testing` holds sweep helpers (coverage assertions). Separation makes imports explicit and keeps each module narrow.
- **A5 uses `tokio::runtime::Builder::new_current_thread()` internally.** Callers don't need an outer runtime; the helper is sync-friendly. Trade-off: if a caller is already inside a runtime, this will panic. Documented in rustdoc. Alternative (taking an executor) was rejected as overkill for a CI helper.
- **CI feature-matrix as a separate job** rather than expanded matrix of the existing `test` job. Keeps per-OS testing decoupled from per-feature testing; matrix × matrix would be 3 OS × 12 feature sets = 36 cells per PR. Too slow. The feature-matrix runs only on Linux (cheapest runner); platform issues surface in the main test job.
- **Rustdoc as a CI-gated job** (RUSTDOCFLAGS=-D warnings) rather than inline in the `test` job. Cleaner separation of what failed.
- **No upstream fix for the clippy `unnecessary_cast` warning in `session_redis.rs`** — it's pre-existing, behind the `session-redis` feature (not exercised by M4), and out of this milestone's allow-list. Flagged as baseline debt in completion summary.

## Mistakes made
- Used `roles: vec![role.to_owned()]` in the first draft of the policy-coverage test, but `Subject::roles` is `SmallVec<[String; 4]>`. Fix: `smallvec::smallvec![role.to_owned()]`. Lesson (repeat of M2): always re-read the type definition before drafting fixtures.
- The `testing::assert_every_route_has_policy` doc example also had the same `vec![..]` issue; caught immediately by the workspace doctest run.

## Root causes
- `Subject` uses `SmallVec` for roles as a micro-optimization. The type shows up in test fixtures that would otherwise look identical to `Vec<String>`. Consider whether to re-expose a `Subject::with_roles(&[&str])` helper in the future — it would make fixture construction less noisy.

## What was harder than expected
- CI workflow YAML: the feature-matrix `strategy.matrix.features` contains an empty string for the `--no-default-features` case. Bash conditional (`if [ -z "${{ matrix.features }}" ]; then ... fi`) handles both the empty case and the non-empty case. Tested the YAML is syntactically valid by re-reading (no YAML linter invoked in-session — the `rustdoc-warnings` job's `RUSTDOCFLAGS` env is a new pattern I'd reuse; verified in docs/literature).

## Naming conventions established
- Boot-time helpers live in `<crate>::boot` module.
- Test/fixture helpers live in `<crate>::testkit` (one-shot mocks).
- Sweep/coverage helpers live in `<crate>::testing` (assertion-shaped).
- CI job names: `feature-matrix`, `rustdoc-warnings`, `supply-chain`, `test` — short kebab-case describing the gate's job.

## Test patterns that worked well
- **Per-test environmental boundary conditions.** `empty_app_env_no_check`, `development_env_no_check`, `staging_allows_dev_source`, `production_rejects_dev_source`, `production_allows_no_dev_source` — five distinct states of the (app_env, has_dev) matrix. Each named after its observable behavior so failures are obvious.

## Missing tests that should exist now
- A CI self-test (run a local workflow-dispatch on the new `feature-matrix` job) wasn't performed in-session. The workflow logic is simple (bash conditional on empty feature string) but a smoke run on PR #1 will be the real validation.

## Rules for the next runbook (future work)
- Gate A is the whole runbook — no M5. Future runbooks that touch these crates should mirror the feature-flag discipline, the framework-neutral-helper pattern, and the doc-first DoD.
- If a follow-up runbook adds `SecureQuery` / `SecurePath` Actix adapters, replay the M1 pattern. If it adds IPv4-mapped IPv6 handling to `SafeUrl`, replay the M3 variant-analysis pattern.

## Template improvements suggested
- The runbook template's "Files Allowed to Change" list should include a "baseline debt" column for pre-existing clippy/fmt issues that will NOT be fixed in the milestone. Currently the allow-list rule forces a conversation when baseline issues are discovered; a formal column would document the decision up front.

# Completion Summary — sg-gate-a Milestone 4

## Goal completed
Sunlit Guardian's two remaining nice-to-have asks (A4, A5) shipped, license posture reconciled (C1), `deny.toml` documented as the canonical downstream policy (C3), and a CI feature-matrix gate installed to prevent backsliding on M1/M2's framework-flag work (Google's "preventing backsliding" pattern). Documentation is first-class: a dev-guide index and production checklist consolidate the four adapter guides and production-boot workflow.

## Files changed
- `crates/secure_identity/src/boot.rs` — NEW: `assert_no_dev_identity_in_production` + `ProductionModeViolation`.
- `crates/secure_identity/src/lib.rs` — added `pub mod boot;` + re-exports.
- `crates/secure_identity/tests/sg_gate_a_boot_assert.rs` — NEW: 6 scenarios.
- `crates/secure_identity/examples/production_boot.rs` — NEW.
- `crates/secure_authz/src/testing.rs` — NEW: `RouteDescriptor`, `PolicyFixture`, `UnmappedRoute`, `assert_every_route_has_policy`.
- `crates/secure_authz/src/lib.rs` — added `pub mod testing;`.
- `crates/secure_authz/tests/sg_gate_a_policy_coverage.rs` — NEW: 4 scenarios.
- `crates/secure_authz/examples/route_coverage.rs` — NEW.
- `crates/secure_authz/Cargo.toml` — new `[[example]]` entries.
- `.github/workflows/ci.yml` — NEW jobs: `feature-matrix` (3 crates × 4 feature combinations = 12 cells), `rustdoc-warnings` (RUSTDOCFLAGS=-D warnings).
- `README.md` — License section, dev-guide index, supply-chain policy pointer.
- `deny.toml` — header comment noting canonical status.
- `docs/dev-guide/README.md` — NEW: dev-guide index.
- `docs/dev-guide/production-checklist.md` — NEW: deployment checklist.
- `docs/slo/completed/RUNBOOK-sunlit-guardian-gate-a.md` — Milestone Tracker: M4 `done`.

## Tests added
- `crates/secure_identity/tests/sg_gate_a_boot_assert.rs` — 6 scenarios covering all (app_env × has_dev_source) states.
- `crates/secure_authz/tests/sg_gate_a_policy_coverage.rs` — 4 scenarios (all covered, one missing, all missing, no fixtures).

Total new tests: **10**.

## Runtime validations added
None additional for M4. A4 helpers run at boot; A5 helpers run in CI — neither is a runtime request-path concern. The CI feature-matrix job itself IS a runtime validation of the feature flags M1/M2 shipped.

## Compatibility checks performed
- `cargo test --workspace` — 1126 passing, 0 failing.
- `cargo test -p secure_identity --test sg_gate_a_boot_assert` — 6 passing.
- `cargo test -p secure_authz --test sg_gate_a_policy_coverage` — 4 passing.
- `cargo test -p secure_identity --doc` — 24 doctests passing.
- `cargo test -p secure_authz --doc` — 25 doctests passing.
- `cargo clippy -p secure_identity --no-deps -- -D warnings` — clean.
- `cargo clippy -p secure_authz --all-features --no-deps -- -D warnings` — clean.
- `cargo build --example production_boot -p secure_identity` — green.
- `cargo build --example route_coverage -p secure_authz` — green.
- License audit: all 13 `crates/*/Cargo.toml` manifests say `license = "MIT"`; README's new License section matches. No divergence existed to reconcile (feedback doc premise was stale).

## Documentation updated
- `secure_identity::boot` rustdoc with full examples (two runnable doctests).
- `secure_authz::testing` rustdoc with full example.
- README License section, dev-guide index, supply-chain pointer.
- `docs/dev-guide/README.md` index.
- `docs/dev-guide/production-checklist.md` — engineer-facing pre-deployment checklist.
- `deny.toml` header comment.

## .gitignore changes
- None required.

## Test artifact cleanup verified
- `git status` shows only intended M4 changes + M1–M3 documentation files still staged from earlier milestones.

## Deferred follow-ups
- Pre-existing clippy warning in `crates/secure_identity/src/session_redis.rs:81` (clippy::unnecessary_cast, behind `session-redis` feature) — untouched by M4. Flagged for a baseline-cleanup PR.
- Pre-existing `security_events::mobile_redaction` clippy warning + fmt drift across mobile crates — flagged in M1 lessons. Still pre-existing.
- CI `feature-matrix` workflow self-test: the YAML passes static inspection but a live smoke run on the first PR will be the real validation.

## Known non-blocking limitations
- `assert_every_route_has_policy` internally spins up a single-thread tokio runtime. If called from inside an existing runtime, it panics. Documented in the rustdoc. Typical consumer is a test / CI harness, so this is the right trade.
- A4 takes `has_dev_identity_source: bool` rather than auto-detecting, because detection logic varies per service. Services with multiple authenticators will need their own detection layer. Documented in the rustdoc and production checklist.

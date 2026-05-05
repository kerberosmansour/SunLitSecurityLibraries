# Lessons Learned — fug Milestone 1

## What changed
- Added `#![forbid(unsafe_code)]` to `crates/secure_smoke_service/src/lib.rs` (the only crate that was missing it).
- Added `crates/security_core/tests/no_unsafe_code.rs` — workspace-level integration test with two assertions: every crate has the attribute; no `unsafe` keyword anywhere in `crates/*/src/`.
- Added `docs/dev-guide/unsafe-budget.md` documenting the posture and the planned cargo-geiger work for M2.
- Updated `README.md` supply-chain policy summary with a memory-safety attestation bullet.
- Updated `CHANGELOG.md` with a user-facing entry.

## Design decisions and why
- **Test lives in `crates/security_core/tests/` not workspace root** — the workspace `Cargo.toml` is a virtual manifest (no `[package]` block). Adding a root package would change Cargo's surface area for downstream contributors and CI in ways that exceed M1's scope. `security_core` is the foundation crate every other crate depends on, so a test there runs in every workspace test run. Same property, lower structural cost.
- **`CRATES_REQUIRING_FORBID` is an explicit constant, not derived from `Cargo.toml`** — this means adding a new workspace crate requires updating the test, which is exactly the deliberation gate we want. A future contributor cannot accidentally add a crate that escapes the forbid posture.
- **Two tests, not one** — the lint attribute test answers "is `forbid` declared?"; the keyword scan answers "is the property actually true in source?" The second is paranoid but cheap, and it is what catches macro-injected unsafe (research called out `tokio::pin!` as a known landmine; this scan finds it even if the lint were somehow bypassed).
- **20-line head window** — `lib.rs` files vary in attribute layout (some have outer doc-comments first, some have multiple attributes before the doc comment). 20 lines covers every observed case and is forgiving enough that future stylistic edits don't trigger false positives.
- **Plain-English failure message** — when the test fails, the operator is told the crate name, the file path, and the remediation (add the attribute, or document an exception in unsafe-budget.md and update `CRATES_REQUIRING_FORBID`). No diff-only output.

## Assumptions verified
- All 13 published crates currently start with `#![forbid(unsafe_code)]` — verified by initial Bash grep before writing the test.
- `secure_smoke_service` was the only crate missing the attribute — verified.
- Zero `unsafe` keywords currently exist in `crates/*/src/` — verified by both manual grep and the new keyword-scan test.
- `tokio::pin!` and `pin-project` are not used in the workspace — verified by Bash grep, which means the macro-injected-unsafe risk research flagged is currently zero.
- Mutation-test confirmed: removing `#![forbid(unsafe_code)]` from any crate makes the test fail with a clear named-crate error.

## Assumptions still unresolved
- Whether `cargo expand` per-crate would reveal *any* macro-introduced unsafe. The keyword-scan test is the safety net; an exhaustive `cargo expand` audit per release is a follow-up if the geiger number (M2) ever ticks up unexpectedly.

## Mistakes made
- First-pass cargo fmt produced diffs in the new test file — auto-fixed without churn. (Self-induced; should have run `cargo fmt --all` immediately after writing the file rather than only `--check`.)

## Root causes
- (No root cause for the fmt issue beyond "didn't run fmt before reading the diff.")

## What was harder than expected
- Nothing material. The runbook called for a workspace-root test; the virtual-manifest reality forced a small relocation, but the property is identical.

## Invariants/assertions added or strengthened
- **Compile-time invariant**: every workspace crate's `lib.rs` (or `main.rs`) must declare `#![forbid(unsafe_code)]` within the first 20 lines, before any item declaration.
- **Build-time invariant**: no `unsafe ` keyword (in code form: `unsafe {`, `unsafe fn`, `unsafe impl`, `unsafe trait`) appears anywhere in `crates/*/src/`.

## Resource bounds established or verified
- The regression test reads at most 14 small files (lib.rs heads) and a finite set of `.rs` files under each `src/`. Bounded; runs in milliseconds in practice.

## Debugging / inspection notes
- Mutation-tested by stripping the attribute from `secure_authz/src/lib.rs` and re-running the test. The failure message correctly names the crate and the file path. After restore, the test passed again. This confirmed the test is not a vacuous pass.

## Naming conventions established
- Workspace-level integration tests live in the foundation crate (`security_core/tests/`) when they assert workspace-wide invariants.
- Plain-English assertion messages with file:line citations are the project convention for cross-cutting tests.

## Test patterns that worked well
- The `CRATES_REQUIRING_FORBID` explicit list — opinionated about new-crate addition.
- The two-assertion pattern (declarative + behavioural) — lint-attr test is the contract; keyword-scan test is the safety net.
- The mutation test as part of execution evidence — confirms the assertion is not vacuously true.

## Missing tests that should exist now
- (Not in M1 scope; cargo-geiger lives in M2 and will measure transitive unsafe.)

## Rules for the next milestone (M2 — `cargo-geiger`)
- Pin the geiger version in CI exactly. Document the version in `unsafe-budget.md`.
- Run with `--all-features` for the official number (worst-case).
- Upload the JSON artifact regardless of pass/fail; the artifact *is* the audit evidence.
- Threshold starts informational only — promotion to blocking is a separate runbook.
- The dev-guide page already has an M2 section drafted; M2 fills it with the actual measured number.

## Template improvements suggested
- v4 runbook M1 BDD scenarios were specific enough to drive execution unchanged.
- The "workspace root tests/" assumption in the runbook was generic Rust advice; for virtual workspaces it needs a footnote. (Updated for future similar runbooks.)

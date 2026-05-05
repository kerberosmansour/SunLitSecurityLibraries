# Completion Summary — fug Milestone 1

## Goal completed
The `#![forbid(unsafe_code)]` posture across every workspace crate is now a regression-tested compile-time invariant. Removing the attribute from any crate fails CI with a named-crate error. A companion scan asserts no `unsafe` keyword appears anywhere in `crates/*/src/`. Consumers and auditors can cite "every workspace crate is forbid(unsafe_code), regression-tested" with confidence.

## Files changed
- `crates/secure_smoke_service/src/lib.rs` — added `#![forbid(unsafe_code)]` (was the only crate without it).
- `crates/security_core/tests/no_unsafe_code.rs` — NEW, two-test regression suite.
- `docs/dev-guide/unsafe-budget.md` — NEW, posture documentation + planned M2 cargo-geiger work.
- `README.md` — added "Memory-safety attestation" bullet to supply-chain policy summary.
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/future/RUNBOOK-forbid-unsafe-and-geiger.md` — M1 marked done in Milestone Tracker.
- `docs/slo/lessons/fug-m1.md` — NEW, lessons-learned file.
- `docs/slo/completion/fug-m1.md` — NEW (this file).

## Tests added
- `crates/security_core/tests/no_unsafe_code.rs::every_workspace_crate_forbids_unsafe_code` — declarative test on lib-root attributes.
- `crates/security_core/tests/no_unsafe_code.rs::no_unsafe_keyword_in_workspace_sources` — behavioural scan for the `unsafe` keyword across `crates/*/src/`.

## Runtime validations added
- Mutation-tested: stripped `#![forbid(unsafe_code)]` from `crates/secure_authz/src/lib.rs`; the regression test failed with a clear named-crate error message; restored and confirmed pass. This is captured in the Evidence Log of the milestone section in the runbook.

## Static analysis and formatter evidence
- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo test -p security_core` — 40 tests pass (15 unit + 7 e2e + 16 sunlit_core_types + 2 no_unsafe_code).

## Compatibility checks performed
- All existing tests in `security_core` continue to pass.
- `secure_smoke_service` still builds (single-line attribute add at top of `lib.rs`).
- All other crates unchanged.
- Existing CI workflows untouched.

## Invariants/assertions added
- **Compile-time invariant** (per crate): `#![forbid(unsafe_code)]` is present at lib-root.
- **Build-time invariant** (workspace): no `unsafe` keyword in any code form within `crates/*/src/`.

## Resource bounds added or verified
- Test reads at most 14 small files plus the per-crate source tree once each. Bounded; runs in milliseconds.

## Documentation updated
- `README.md` — Supply-Chain Security policy summary.
- `docs/dev-guide/unsafe-budget.md` — NEW.
- `CHANGELOG.md` — Unreleased entry.

## .gitignore changes
- None required. The test produces no on-disk artifacts.

## Test artifact cleanup verified
- `git status` shows only the intentional files; no untracked test artifacts.

## Deferred follow-ups
- M2 (`cargo-geiger` CI lane + workspace number + threshold) — separate issue (#17).
- Promotion of M2's threshold from informational to blocking — separate runbook after one release cycle of stable signal.

## Known non-blocking limitations
- The keyword-scan test catches `unsafe { … }`, `unsafe fn`, `unsafe impl`, `unsafe trait`. It would not catch `unsafe` introduced via macro expansion that the source file does not literally contain — but `forbid(unsafe_code)` itself catches that at compile time. The scan is a belt-and-braces sanity check, not the primary gate.

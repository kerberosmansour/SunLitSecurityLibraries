# Unsafe Code Budget

> Status: M1 (regression-tested forbid posture) is complete. M2 (transitive `cargo-geiger` number + threshold) is the next milestone of the [`forbid-unsafe-and-geiger`](../slo/future/RUNBOOK-forbid-unsafe-and-geiger.md) runbook.

## Posture

Every crate in this workspace declares `#![forbid(unsafe_code)]` at lib-root. This is the strongest available compile-time guarantee against `unsafe` Rust:

- `forbid` cannot be locally overridden by `#[allow(unsafe_code)]` on a function or block. Once forbidden, an `unsafe { … }` block in that crate is a hard compile error, no exceptions.
- `deny` (the weaker form) can be locally overridden. SunLit deliberately picks `forbid` to remove the judgment call.

| Crate | Posture | Notes |
|---|---|---|
| `security_core` | `forbid(unsafe_code)` | foundation crate; no FFI |
| `secure_errors` | `forbid(unsafe_code)` | also `deny(clippy::all, clippy::pedantic)` |
| `security_events` | `forbid(unsafe_code)` | |
| `secure_boundary` | `forbid(unsafe_code)` | |
| `secure_authz` | `forbid(unsafe_code)` | |
| `secure_data` | `forbid(unsafe_code)` | crypto crate; AEAD via RustCrypto and (gated) `aws-lc-rs` for FIPS — neither requires application-layer unsafe |
| `secure_output` | `forbid(unsafe_code)` | |
| `secure_identity` | `forbid(unsafe_code)` | |
| `secure_device_trust` | `forbid(unsafe_code)` | |
| `secure_network` | `forbid(unsafe_code)` | TLS via `rustls` |
| `secure_resilience` | `forbid(unsafe_code)` | |
| `secure_privacy` | `forbid(unsafe_code)` | |
| `secure_reference_service` | `forbid(unsafe_code)` | private workspace crate |
| `secure_smoke_service` | `forbid(unsafe_code)` | private workspace crate; added in M1 |

## Regression test

[`crates/security_core/tests/no_unsafe_code.rs`](../../crates/security_core/tests/no_unsafe_code.rs) runs as part of the standard `cargo test --workspace` chain on every PR. It contains two tests:

1. **`every_workspace_crate_forbids_unsafe_code`** — reads each crate's `lib.rs` (or `main.rs`) and asserts `#![forbid(unsafe_code)]` appears within the first 20 lines, before any item declaration. Failure names the offending crate and the file path.
2. **`no_unsafe_keyword_in_workspace_sources`** — recursively scans every crate's `src/` for the `unsafe` keyword in code form (`unsafe {`, `unsafe fn`, `unsafe impl`, `unsafe trait`). Comment lines are skipped. The assertion is "must be empty"; any match fails the build with a file:line citation.

Adding a new workspace crate requires updating the `CRATES_REQUIRING_FORBID` constant in that test file. The constant is intentionally manual — adding a new crate to the workspace should be a deliberate decision about its unsafe posture.

### Why not at workspace root?

The workspace root has no `[package]` block (it is a virtual manifest). Putting the test inside `security_core/tests/` gives it the same execution surface — every CI test run executes it — without the structural cost of converting the root into a hybrid root-package. `security_core` is the foundation crate every other crate depends on, so the test runs whenever any workspace test runs.

## Planned: transitive `cargo-geiger` number (M2)

`cargo-geiger` measures the count of `unsafe` blocks in the *dependency tree* (transitive). SunLit's source code is `unsafe`-free; dependencies are not, so the published number is non-zero and the goal is to make the change *visible* on every PR.

The M2 design (per the [runbook](../slo/future/RUNBOOK-forbid-unsafe-and-geiger.md#milestone-2--cargo-geiger-in-supply-chain-ci-published-workspace-number-documented-threshold)):

- Pin the geiger version in CI.
- Run `cargo geiger --workspace --all-features --output-format Json` on every PR.
- Upload `output/cargo-geiger.json` as a build artifact.
- Publish the workspace number in this README section.
- Document a threshold = current measured baseline + 10% headroom.

### Threshold semantics

The threshold starts **informational** (advisory). It is a delta-detector, not a gate. A PR that pushes the number above the threshold means a transitive dependency introduced new unsafe code; the reviewer reads the artifact diff to decide whether the change is acceptable.

Promotion to a blocking CI gate is a separate runbook, planned after the metric has been observed for at least one release cycle and false-positive patterns are understood.

## When `unsafe` is genuinely needed

Should a future capability legitimately require `unsafe` code (e.g., a no_std embedded port, a SIMD primitive, or a low-level FFI shim that cannot be expressed safely):

1. The new crate **does not** start with `#![forbid(unsafe_code)]`. It starts with `#![deny(unsafe_code)]`.
2. Each `#[allow(unsafe_code)]` site is named with a doc comment that includes:
   - the safety argument (why this `unsafe` is sound)
   - the regression test that exercises the soundness condition
   - the threat-model row (`tm-<slug>-…`) that the unsafe site addresses
3. The crate is added to `docs/dev-guide/unsafe-budget.md` with the exception, the rationale, and a link to the named call sites.
4. `CRATES_REQUIRING_FORBID` in the regression test is updated accordingly.

This keeps the explicit-exception path documented and reviewable, rather than silent.

## Related

- Runbook: [`docs/slo/future/RUNBOOK-forbid-unsafe-and-geiger.md`](../slo/future/RUNBOOK-forbid-unsafe-and-geiger.md)
- Research dossier: [`docs/slo/research/forbid-unsafe-and-geiger/`](../slo/research/forbid-unsafe-and-geiger/)
- Supply-chain policy: [`deny.toml`](../../deny.toml)
- Threat model: [`THREAT_MODEL.md`](../../THREAT_MODEL.md)

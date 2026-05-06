# Unsafe Code Budget

> Status: M1 (regression-tested forbid posture) and M2 (`cargo-geiger` advisory CI lane + workspace number) are complete. Promotion of the threshold to a blocking gate is a separate, future runbook.

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

## Transitive `cargo-geiger` number

`cargo-geiger` measures the count of `unsafe` blocks in the *dependency tree* (transitive). SunLit's source code is `unsafe`-free; dependencies are not, so the published number is non-zero and the goal is to make the change *visible* on every PR.

### How the number is produced

| Field | Value |
|---|---|
| Tool | [`cargo-geiger`](https://github.com/rust-secure-code/cargo-geiger) |
| Version (pinned) | `0.13.0` (per research dossier — active but partial maintenance; no drop-in successor; staying on it is the recommended posture) |
| Root package | `secure_reference_service` (depends on every library crate; closest analogue to a downstream consumer's BOM) |
| Invocation | `cd crates/secure_reference_service && cargo geiger --all-features --output-format Json --update-readme=false` |
| CI lane | `.github/workflows/ci.yml` → `supply-chain` job → "Cargo geiger" step (advisory, `continue-on-error: true`, 10-minute timeout) |
| Artifact | `output/cargo-geiger.json` uploaded by the `actions/upload-artifact` step (30-day retention) |
| Local equivalent | `bash scripts/audit.sh` (or `pwsh scripts/audit.ps1`) runs the same invocation and writes the same path |

`--all-features` is the deliberate choice: the number reflects the worst case across every published feature of the reference service. The reference service depends transitively on every published library; consumers who pull a narrower set of crates will encounter a smaller footprint.

### Why not `--workspace`?

`cargo-geiger` requires a single root package — it cannot consume a virtual manifest. The reference service is the chosen root for two reasons: (1) it depends on every library crate, so its dep graph is a superset of any other single library's dep graph; (2) it is the canonical "what does a downstream service look like" example shipped with the workspace, so the published number reflects what an integrator's audit would also report. A future enhancement could iterate per published library and report a max-of, but the reference-service number is the current published value.

### Current measured baseline

| Metric | Value (as of 2026-05-05, root = `secure_reference_service`, `--all-features`) |
|---|---:|
| Unsafe expressions used / available | **22 636 / 48 192** |
| Unsafe items used / available | 242 / 1 200 |
| Unsafe `fn` used / available | 582 / 745 |
| Unsafe methods used / available | 74 / 82 |
| Unsafe trait `impl` used / available | 828 / 1 274 |
| SunLit crates with unsafe usage | 0 of 14 (every workspace crate is `:)` — `forbid(unsafe_code)` declared, no unsafe used) |

The headline is **22 636 transitive unsafe expressions used**. Common offenders are core ecosystem crates (`tokio`, `time`, `serde_json`, `tracing-subscriber`, `hyper`) — all well-audited primitives. The CI artifact (`cargo-geiger.json`) is the source of truth on every main-branch run; this section is updated on a release-cycle cadence to track the long-term trend.

### M2 `secure_data` + `pq` attempt

M2 adds the opt-in `secure_data` `pq` feature (`ml-kem`, `x25519-dalek`, `hkdf`, `sha2`). The milestone attempted to measure the feature-local dependency tree directly:

| Field | Value |
|---|---|
| Invocation | `cd crates/secure_data && timeout 60 cargo geiger --features pq --update-readme=false` |
| Result | timed out with exit 124 before producing a count |
| Tool behavior | `cargo-geiger` v0.13.0 repeatedly emitted `Failed to match (ignoring source)` lines for registry packages in the resolved workspace graph |
| Retry evidence | a second `--output-format Json` run with a 180-second timeout also exited 124 and left a zero-byte JSON artifact |
| Follow-up | keep the reference-service advisory lane as the tracked workspace metric; retry this feature-local measurement when cargo-geiger can complete on the current graph |

This is recorded as an evidence caveat, not as a changed threshold. The project source posture is unchanged: every SunLit crate still declares `#![forbid(unsafe_code)]`, and the PQ implementation adds no application-layer `unsafe`.

### Threshold

| Threshold | Value | Source of truth |
|---|---:|---|
| Baseline | 22 636 | CI artifact + this section |
| Informational threshold | 24 900 (= baseline + 10 % headroom) | this section |
| Action triggered when number exceeds threshold | reviewer downloads CI artifact and diffs against the previous main-branch run; classifies the new unsafe (acceptable / replaceable / questionable); posts the finding in the PR | (operator behavior) |

### Threshold semantics

The threshold starts **informational** (advisory). It is a delta-detector, not a gate. A PR that pushes the number above the threshold means a transitive dependency introduced new unsafe code; the reviewer reads the artifact diff to decide whether the change is acceptable.

The advisory CI step uses `continue-on-error: true` so failures (e.g., new unsafe in a dep, or geiger itself failing) do not block merges. They surface as a yellow check on the PR, with the JSON artifact downloadable from the run summary for diff review.

Promotion to a blocking CI gate is a separate runbook, planned after the metric has been observed for at least one release cycle and false-positive patterns are understood. Promotion criteria:

1. The metric has been stable across ≥1 release cycle.
2. Common transient noise sources (e.g., toolchain-version-driven changes in `proc-macro2` / `serde`) are characterised.
3. A defined response procedure exists for "geiger went up" events (review artifact diff, classify, decide accept-or-revert).
4. The release-process doc names cargo-geiger as a release gate.

### Reviewing a PR that changed the number

1. Click the cargo-geiger artifact on the PR's CI run.
2. Compare against the artifact from main branch's last run.
3. The diff identifies the dep that introduced new unsafe.
4. Decide: accept (the dep is necessary; the unsafe is in a well-audited primitive), revert (the dep is replaceable), or escalate (the dep is questionable; open a discussion).

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

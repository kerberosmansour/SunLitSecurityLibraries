# ANSSI Rust Secure Coding Guidelines — Compliance Mapping

> **Pin:** ANSSI [`rust-guide`](https://github.com/ANSSI-FR/rust-guide) commit [`84e6ae181712c9ed797aeaf695c9965a13a1d5fa`](https://github.com/ANSSI-FR/rust-guide/tree/84e6ae181712c9ed797aeaf695c9965a13a1d5fa) (2026-04-07). Site banner reads "Secure Rust Guidelines (unstable)" — pinning is by commit SHA, not by tag. Refreshing the pin is a deliberate, CHANGELOG-tracked update.
>
> **Status:** M2 of the [`anssi-rust-compliance`](../slo/future/RUNBOOK-anssi-rust-compliance.md) runbook — all 61 rules classified with concrete evidence pointers, explicit partial-coverage notes, or named compensating controls. M3 lands a CI lint that fails the build on dead pointers.
>
> **Leverage framing (per research):** NIS2 (Implementing Regulation 2024/2690) and the EU Cyber Resilience Act (Reg. 2024/2847) do **not** cite the ANSSI Rust guide directly. The guide's leverage is "state-of-the-art evidence in French / IEC 62443-4-1 SD-3 audits" — useful for procurement, not "NIS2 compliance" or "CRA compliance." Do not claim the latter.

## Family summary

| Family | Count | ANSSI source files | Tooling overlap (research estimate) |
|---|---:|---|---|
| **DENV** — development environment | 8 | [`src/en/devenv.md`](https://github.com/ANSSI-FR/rust-guide/blob/84e6ae181712c9ed797aeaf695c9965a13a1d5fa/src/en/devenv.md) | high (toolchain, cargo, fmt, clippy, audit) |
| **LIBS** — third-party dependencies | 5 | [`src/en/libraries.md`](https://github.com/ANSSI-FR/rust-guide/blob/84e6ae181712c9ed797aeaf695c9965a13a1d5fa/src/en/libraries.md) | high (`cargo-deny`, `cargo-audit`, `cargo-outdated`, `cargo-geiger`) |
| **LANG** — language constructs | 16 | `naming.md`, `integer.md`, `errors.md`, `standard.md`, `unsafe/generalities.md` | partial (clippy default + restriction groups) |
| **MEM** — memory management | 10 | `unsafe/memory.md`, `standard.md` (`MEM-MUT-REC-RC`) | partial — most rules N/A under `forbid(unsafe_code)` |
| **FFI** — foreign function interface | 21 | [`src/en/unsafe/ffi.md`](https://github.com/ANSSI-FR/rust-guide/blob/84e6ae181712c9ed797aeaf695c9965a13a1d5fa/src/en/unsafe/ffi.md) | minimal — most rules N/A in pure-safe libs |
| **UNSAFE** — umbrella | 1 | `unsafe/generalities.md` (`UNSAFE-NOUB`) | high — automatically satisfied under `forbid(unsafe_code)` |
| **Total** | **61** | | |

## Status enum

- **`compliant`** — the rule is satisfied, with a concrete evidence pointer in the Evidence column.
- **`partial`** — partially satisfied; specifics in Notes.
- **`waived`** — deliberately not followed; Notes name a compensating control.
- **`N/A`** — not applicable to this codebase; Notes give the reason (e.g., the rule is FFI-only and the workspace is `forbid(unsafe_code)`).
- **`unfilled`** — retired M1 placeholder; no M2 row may use it.

## Rule index

### DENV — development environment (8 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `DENV-STABLE` | Rule | Use a stable compilation toolchain | `compliant` | `.github/workflows/ci.yml:65` | CI installs the stable Rust toolchain for the workspace test matrix. |
| `DENV-TIERS` | Rule | Exclusive use of tier 1 of `rustc` for safety-critical software | `compliant` | `.github/workflows/ci.yml:58` | The supported CI matrix covers Linux, macOS, and Windows hosted runners; unsupported targets are outside the published support posture. |
| `DENV-CARGO-LOCK` | Rule | Track `Cargo.lock` in version control system | `compliant` | `Cargo.lock:1` | The workspace lockfile is committed and used by CI/supply-chain tooling. |
| `DENV-CARGO-OPTS` | Rule | Keep default values for critical variables in cargo profiles | `compliant` | `Cargo.toml:1` | The workspace root defines no `[profile.*]` overrides; Cargo profile defaults are retained. |
| `DENV-CARGO-ENVVARS` | Rule | Keep default values for compiler environment variables when running cargo | `compliant` | `.github/workflows/ci.yml:71` | CI cargo build/test/lint invocations do not override compiler environment variables; rustdoc only sets `RUSTDOCFLAGS=-D warnings` for documentation warnings. |
| `DENV-FORMAT` | Recommendation | Use Rust formatter (rustfmt) | `compliant` | `.github/workflows/ci.yml:71` | `cargo fmt --all -- --check` runs on every PR. |
| `DENV-LINTER` | Rule | Use linter regularly | `compliant` | `.github/workflows/ci.yml:74` | `cargo clippy --workspace --all-targets -- -D warnings` runs on every PR. |
| `DENV-AUTOFIX` | Rule | Manually check automatic fixes | `waived` | `.github/PULL_REQUEST_TEMPLATE.md:33` | Compensating control: reviewer-owned PR review. CI does not run `cargo fix`/auto-fix steps; any auto-fix output must appear as an ordinary diff and be reviewed through the PR template. |

### LIBS — third-party dependencies (5 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `LIBS-VETTING-DIRECT` | Rule | Validation of Direct Third-Party Dependencies | `compliant` | `.github/workflows/ci.yml:202` | `cargo vet --locked` runs in CI and consumes the workspace cargo-vet policy. |
| `LIBS-VETTING-TRANSITIVE` | Recommendation | Validation of Transitive Third-Party Dependencies | `compliant` | `supply-chain/config.toml:7` | cargo-vet imports trusted third-party audit sets and records exemptions for transitive dependencies. |
| `LIBS-OUTDATED` | Rule | Check for outdated dependencies (`cargo-outdated`) | `waived` | `.github/dependabot.yml:3` | Compensating control: weekly Dependabot Cargo update PRs. The workspace does not run `cargo-outdated`; dependency freshness is handled through scheduled Dependabot review plus audit/deny/vet gates. |
| `LIBS-AUDIT` | Rule | Check for security vulnerability reports on dependencies (`cargo-audit`) | `compliant` | `.github/workflows/ci.yml:196` | `cargo audit` runs in the CI supply-chain job and local `scripts/audit.sh`. |
| `LIBS-UNSAFE` | Recommendation | Check for unsafe code in dependencies | `compliant` | `.github/workflows/ci.yml:208` | `cargo-geiger` runs as an advisory CI lane and uploads the transitive unsafe report artifact. |

### LANG — language constructs (16 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `LANG-NAMING` | Rule | Respect naming conventions | `compliant` | `clippy::style` | The CI clippy gate covers Rust naming/style lint groups and fails on warnings. |
| `LANG-ARITH` | Rule | Use appropriate arithmetic operations regarding potential overflows | `partial` | `docs/slo/research/anssi-rust-compliance/dossier.md:46` | Arithmetic-side-effect restriction lint is identified but not enforced workspace-wide; current coverage is code review plus targeted tests. |
| `LANG-ERRWRAP` | Recommendation | Implement custom `Error` type wrapping all possible errors | `compliant` | `crates/secure_data/src/error.rs:15` | Published crates expose explicit error enums/structs rather than raw dependency errors at API boundaries. |
| `LANG-LIMIT-PANIC` | Rule | Limit `panic` use | `partial` | `crates/secure_errors/src/panic.rs:13` | Service-boundary panic handling exists, but the workspace still contains intentional test/dev panics and some explicit panic paths. |
| `LANG-LIMIT-PANIC-SRC` | Rule | Limit use of `panic`-ing functions | `partial` | `docs/slo/research/anssi-rust-compliance/dossier.md:46` | `clippy::panic`, `clippy::unwrap_used`, and `clippy::expect_used` are documented as controls but are not enforced globally; tests use `unwrap`/`expect` heavily. |
| `LANG-ARRINDEXING` | Rule | Test properly array indexing or use the `get` method | `partial` | `docs/slo/research/anssi-rust-compliance/dossier.md:46` | `clippy::indexing_slicing` is not enforced workspace-wide; coverage comes from fuzz/property tests and targeted code review of indexing paths. |
| `LANG-SYNC-TRAITS` | Rule | Justify `Send` and `Sync` implementation | `compliant` | `crates/security_core/tests/no_unsafe_code.rs:167` | The workspace has no `unsafe impl Send/Sync`; auto traits are compiler-derived. |
| `LANG-CMP-INV` | Rule | Respect the invariants of standard comparison traits | `compliant` | `clippy::derive_ord_xor_partial_ord` | Clippy's comparison-trait lints are covered by the CI clippy gate. |
| `LANG-CMP-DEFAULTS` | Recommendation | Use the default method implementation of standard comparison traits | `compliant` | `clippy::partialeq_ne_impl` | CI clippy catches non-default comparison helpers; code review favours derived implementations. |
| `LANG-CMP-DERIVE` | Recommendation | Derive comparison traits when possible | `compliant` | `crates/security_core/src/classification.rs:22` | Core ordered value types derive comparison traits instead of hand-writing comparison logic. |
| `LANG-DROP` | Rule | Justify `Drop` implementation | `compliant` | `crates/security_events/src/hmac.rs:85` | Custom `Drop` implementations are limited to cleanup/zeroization or batch-flush behaviour. |
| `LANG-DROP-NO-PANIC` | Rule | Do not panic in `Drop` implementation | `partial` | `crates/security_events/src/sink.rs:383` | Most `Drop` paths are simple cleanup, but `BatchingSink::drop` currently calls `expect("batch worker mutex poisoned")`; this remains a tracked caveat. |
| `LANG-DROP-NO-CYCLE` | Rule | Do not allow cycles of reference-counted `Drop` | `compliant` | `crates/secure_authz/src/actix/middleware.rs:113` | `Rc` is used for Actix service handles without back-edges or custom `Drop`; code search found no reference-counted cycles. |
| `LANG-DROP-SEC` | Rule | Do not rely only on `Drop` to ensure security | `compliant` | `crates/secure_data/src/secret.rs:9` | Secret wrappers redact `Debug`/Serde output and expose secrets explicitly; drop-time zeroization is an additional control, not the only one. |
| `LANG-UNSAFE` | Rule | Don't use unsafe blocks | `compliant` | `crates/security_core/tests/no_unsafe_code.rs:64` | Regression test requires `#![forbid(unsafe_code)]` at every workspace crate root. |
| `LANG-UNSAFE-ENCP` | Rule | Encapsulation of *unsafe* features | `compliant` | `crates/security_core/tests/no_unsafe_code.rs:108` | No application crate has unsafe blocks/functions/impls to encapsulate; the scan asserts the source tree is empty of unsafe keyword forms. |

### MEM — memory management (10 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `MEM-MUT-REC-RC` | Rule | Avoid cyclic reference-counted pointers | `compliant` | `crates/secure_authz/src/actix/middleware.rs:113` | `Rc` appears only in Actix middleware service handles; no reference-counted cycle or `Drop` graph is present. |
| `MEM-NO-LEAK` | Rule | No memory leak | `partial` | `docs/dev-guide/unsafe-budget.md:7` | `forbid(unsafe_code)` and zeroization reduce leak risk, but Rust safe code can still intentionally leak or create logical retention bugs; this remains code-review governed. |
| `MEM-FORGET` | Rule | Do not use `mem::forget` | `compliant` | `clippy::mem_forget` | Code search found no `mem::forget`; the lint is the documented ANSSI-aligned detector. |
| `MEM-FORGET-LINT` | Recommendation | Use clippy lint to detect use of `mem::forget` | `partial` | `docs/slo/research/anssi-rust-compliance/dossier.md:46` | The lint is identified as the right control, but the workspace does not yet enforce the Clippy restriction group globally. |
| `MEM-LEAK` | Rule | Do not use `leak` function | `compliant` | `crates/security_core/tests/no_unsafe_code.rs:108` | Code search found no `Box::leak`, `String::leak`, or `Vec::leak` in workspace sources; safe-code review remains the control. |
| `MEM-MANUALLYDROP` | Rule | Do release value wrapped in `ManuallyDrop` | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | The workspace does not use `ManuallyDrop`; no release obligation exists. |
| `MEM-NORAWPOINTER` | Rule | Do not convert smart pointer into raw pointer in Rust without `unsafe` | `compliant` | `crates/security_core/tests/no_unsafe_code.rs:108` | Raw-pointer ownership conversions are absent, and `forbid(unsafe_code)` prevents the unsafe dereference/reconstruction side of such patterns. |
| `MEM-INTOFROMRAWALWAYS` | Rule | Always call `from_raw` on `into_raw`-ed value | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | The workspace does not use `into_raw`/`from_raw` ownership handoff patterns. |
| `MEM-INTOFROMRAWONLY` | Rule | Call `from_raw` *only* on `into_raw`-ed value | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No `from_raw` reconstruction exists in published crate sources. |
| `MEM-UNINIT` | Rule | Do not use uninitialized memory | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | Uninitialized-memory APIs require unsafe patterns that are absent under the workspace `forbid(unsafe_code)` posture. |

### FFI — foreign function interface (21 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `FFI-SAFEWRAPPING` | Recommendation | Provide safe wrapping to foreign library | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No published SunLit crate exposes or wraps a foreign-function interface. |
| `FFI-CTYPE` | Rule | Use only C-compatible types in FFI | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No FFI boundary exists; `forbid(unsafe_code)` blocks the required unsafe implementation surface. |
| `FFI-TCONS` | Rule | Use consistent types at FFI boundaries | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No FFI boundary exists. |
| `FFI-AUTOMATE` | Recommendation | Use automatic binding generator tools | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No bindings are generated because no foreign library is bound. |
| `FFI-PFTYPE` | Rule | Use portable aliases `c_*` when binding to platform-dependent types | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No platform-dependent C binding surface exists. |
| `FFI-CKNONROBUST` | Rule | Do not use unchecked non-robust foreign values | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No foreign values cross into the workspace API. |
| `FFI-CKINRUST` | Recommendation | Check foreign values in Rust | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No FFI ingress exists to validate. |
| `FFI-CK-PTR-VALID` | Rule | Check foreign pointers | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No foreign pointers enter published crate APIs. |
| `FFI-INPUT-PTR` | Recommendation | Use raw pointer to encode pointers coming from the external language | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No external-language pointer input exists. |
| `FFI-CK-INPUT-REF-VALID` | Rule | Do not use unchecked foreign references | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No foreign references enter published crate APIs. |
| `FFI-MARKEDFUNPTR` | Rule | Mark function pointer types in FFI as `extern` and `unsafe` | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No FFI function pointer types are defined. |
| `FFI-CKFUNPTR` | Rule | Check foreign function pointers | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No foreign function pointers enter the workspace. |
| `FFI-NOENUM` | Rule | Do not use incoming Rust `enum` at FFI boundary | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No FFI boundary exists where Rust enums could cross. |
| `FFI-R-OPAQUE` | Recommendation | Use dedicated Rust types for foreign opaque types | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No foreign opaque types are represented. |
| `FFI-C-OPAQUE` | Recommendation | Use incomplete C/C++ `struct` pointers to make type opaque | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No C/C++ binding surface exists. |
| `FFI-CK-REF-MODEL` | Rule | Preservation of Rust's memory model when transferring indirections at its boundary | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No indirections cross an FFI boundary. |
| `FFI-MEM-NODROP` | Rule | Do not use types that implement `Drop` at FFI boundary | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No FFI boundary exists, so no `Drop` type crosses one. |
| `FFI-MEM-OWNER` | Rule | Ensure clear data ownership in FFI | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No FFI ownership transfer exists. |
| `FFI-MEM-WRAPPING` | Recommendation | Wrap foreign data in memory-releasing wrapper | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No foreign allocation is acquired or released by SunLit crates. |
| `FFI-NOPANIC` | Recommendation | Handle `panic!` correctly in FFI | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | No panic can cross a non-existent FFI boundary. |
| `FFI-CAPI` | Rule | Expose dedicated C-compatible API only | `N/A` | `crates/security_core/tests/no_unsafe_code.rs:108` | SunLit exposes Rust crate APIs only; no C-compatible API is published. |

### UNSAFE — umbrella (1 rule)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `UNSAFE-NOUB` | Rule | No Undefined Behavior | `compliant` | `crates/security_core/tests/no_unsafe_code.rs:64` | Every workspace crate is required to declare `#![forbid(unsafe_code)]`; no local unsafe code can introduce UB. |

## Documented Deviations

| Rule | Status | Compensating control | Evidence | Rationale |
|---|---|---|---|---|
| DENV-AUTOFIX | waived | Reviewer-owned PR review | `.github/PULL_REQUEST_TEMPLATE.md:33` | The workspace does not run automatic code-fix tools in CI. Any developer-generated auto-fix is reviewed as normal source diff. |
| LIBS-OUTDATED | waived | Weekly Dependabot Cargo update PRs | `.github/dependabot.yml:3` | Dependency freshness is handled by scheduled update PRs rather than a dedicated `cargo-outdated` gate. Audit, deny, and vet still run on every PR. |

## Refresh procedure

1. Open a runbook. The current ANSSI pin (`84e6ae18`) is intentional; bumping it is a deliberate, scoped change.
2. Compare the pinned commit's rule set against the latest commit on `master`. Note added / removed / renamed rules.
3. Update the family-summary counts and the per-rule rows.
4. Re-classify any row whose rule meaning changed.
5. Update the pin reference in the header and in `docs/compliance/README.md`.
6. Add a CHANGELOG entry under "Unreleased."

## Related

- [Runbook `anssi-rust-compliance`](../slo/future/RUNBOOK-anssi-rust-compliance.md)
- [Research dossier](../slo/research/anssi-rust-compliance/dossier.md)
- [Research synthesis](../slo/research/anssi-rust-compliance/synthesis.md)
- [`THREAT_MODEL.md`](../../THREAT_MODEL.md) — OWASP / MASVS / NIST / IEC 62443 / SOC 2 mappings
- [`docs/dev-guide/unsafe-budget.md`](../dev-guide/unsafe-budget.md) — workspace `forbid(unsafe_code)` posture (informs M2 evidence pointers for `LANG-UNSAFE`, `LANG-UNSAFE-ENCP`, `UNSAFE-NOUB`)

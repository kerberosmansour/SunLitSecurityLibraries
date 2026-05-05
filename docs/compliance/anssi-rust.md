# ANSSI Rust Secure Coding Guidelines — Compliance Mapping

> **Pin:** ANSSI [`rust-guide`](https://github.com/ANSSI-FR/rust-guide) commit [`84e6ae181712c9ed797aeaf695c9965a13a1d5fa`](https://github.com/ANSSI-FR/rust-guide/tree/84e6ae181712c9ed797aeaf695c9965a13a1d5fa) (2026-04-07). Site banner reads "Secure Rust Guidelines (unstable)" — pinning is by commit SHA, not by tag. Refreshing the pin is a deliberate, CHANGELOG-tracked update.
>
> **Status:** M1 of the [`anssi-rust-compliance`](../slo/future/RUNBOOK-anssi-rust-compliance.md) runbook — rule index bootstrapped from the ANSSI source files at the pinned commit. All 61 rules listed; Status column carries the `unfilled` placeholder for now. M2 fills evidence pointers and named compensating controls. M3 lands a CI lint that fails the build on dead pointers.
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
- **`unfilled`** — M1 placeholder; M2 must replace.

## Rule index

### DENV — development environment (8 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `DENV-STABLE` | Rule | Use a stable compilation toolchain | `unfilled` | | |
| `DENV-TIERS` | Rule | Exclusive use of tier 1 of `rustc` for safety-critical software | `unfilled` | | |
| `DENV-CARGO-LOCK` | Rule | Track `Cargo.lock` in version control system | `unfilled` | | |
| `DENV-CARGO-OPTS` | Rule | Keep default values for critical variables in cargo profiles | `unfilled` | | |
| `DENV-CARGO-ENVVARS` | Rule | Keep default values for compiler environment variables when running cargo | `unfilled` | | |
| `DENV-FORMAT` | Recommendation | Use Rust formatter (rustfmt) | `unfilled` | | |
| `DENV-LINTER` | Rule | Use linter regularly | `unfilled` | | |
| `DENV-AUTOFIX` | Rule | Manually check automatic fixes | `unfilled` | | |

### LIBS — third-party dependencies (5 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `LIBS-VETTING-DIRECT` | Rule | Validation of Direct Third-Party Dependencies | `unfilled` | | |
| `LIBS-VETTING-TRANSITIVE` | Recommendation | Validation of Transitive Third-Party Dependencies | `unfilled` | | |
| `LIBS-OUTDATED` | Rule | Check for outdated dependencies (`cargo-outdated`) | `unfilled` | | |
| `LIBS-AUDIT` | Rule | Check for security vulnerability reports on dependencies (`cargo-audit`) | `unfilled` | | |
| `LIBS-UNSAFE` | Recommendation | Check for unsafe code in dependencies | `unfilled` | | |

### LANG — language constructs (16 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `LANG-NAMING` | Rule | Respect naming conventions | `unfilled` | | |
| `LANG-ARITH` | Rule | Use appropriate arithmetic operations regarding potential overflows | `unfilled` | | |
| `LANG-ERRWRAP` | Recommendation | Implement custom `Error` type wrapping all possible errors | `unfilled` | | |
| `LANG-LIMIT-PANIC` | Rule | Limit `panic` use | `unfilled` | | |
| `LANG-LIMIT-PANIC-SRC` | Rule | Limit use of `panic`-ing functions | `unfilled` | | |
| `LANG-ARRINDEXING` | Rule | Test properly array indexing or use the `get` method | `unfilled` | | |
| `LANG-SYNC-TRAITS` | Rule | Justify `Send` and `Sync` implementation | `unfilled` | | |
| `LANG-CMP-INV` | Rule | Respect the invariants of standard comparison traits | `unfilled` | | |
| `LANG-CMP-DEFAULTS` | Recommendation | Use the default method implementation of standard comparison traits | `unfilled` | | |
| `LANG-CMP-DERIVE` | Recommendation | Derive comparison traits when possible | `unfilled` | | |
| `LANG-DROP` | Rule | Justify `Drop` implementation | `unfilled` | | |
| `LANG-DROP-NO-PANIC` | Rule | Do not panic in `Drop` implementation | `unfilled` | | |
| `LANG-DROP-NO-CYCLE` | Rule | Do not allow cycles of reference-counted `Drop` | `unfilled` | | |
| `LANG-DROP-SEC` | Rule | Do not rely only on `Drop` to ensure security | `unfilled` | | |
| `LANG-UNSAFE` | Rule | Don't use unsafe blocks | `unfilled` | | |
| `LANG-UNSAFE-ENCP` | Rule | Encapsulation of *unsafe* features | `unfilled` | | |

### MEM — memory management (10 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `MEM-MUT-REC-RC` | Rule | Avoid cyclic reference-counted pointers | `unfilled` | | |
| `MEM-NO-LEAK` | Rule | No memory leak | `unfilled` | | |
| `MEM-FORGET` | Rule | Do not use `mem::forget` | `unfilled` | | |
| `MEM-FORGET-LINT` | Recommendation | Use clippy lint to detect use of `mem::forget` | `unfilled` | | |
| `MEM-LEAK` | Rule | Do not use `leak` function | `unfilled` | | |
| `MEM-MANUALLYDROP` | Rule | Do release value wrapped in `ManuallyDrop` | `unfilled` | | |
| `MEM-NORAWPOINTER` | Rule | Do not convert smart pointer into raw pointer in Rust without `unsafe` | `unfilled` | | |
| `MEM-INTOFROMRAWALWAYS` | Rule | Always call `from_raw` on `into_raw`-ed value | `unfilled` | | |
| `MEM-INTOFROMRAWONLY` | Rule | Call `from_raw` *only* on `into_raw`-ed value | `unfilled` | | |
| `MEM-UNINIT` | Rule | Do not use uninitialized memory | `unfilled` | | |

### FFI — foreign function interface (21 rules)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `FFI-SAFEWRAPPING` | Recommendation | Provide safe wrapping to foreign library | `unfilled` | | |
| `FFI-CTYPE` | Rule | Use only C-compatible types in FFI | `unfilled` | | |
| `FFI-TCONS` | Rule | Use consistent types at FFI boundaries | `unfilled` | | |
| `FFI-AUTOMATE` | Recommendation | Use automatic binding generator tools | `unfilled` | | |
| `FFI-PFTYPE` | Rule | Use portable aliases `c_*` when binding to platform-dependent types | `unfilled` | | |
| `FFI-CKNONROBUST` | Rule | Do not use unchecked non-robust foreign values | `unfilled` | | |
| `FFI-CKINRUST` | Recommendation | Check foreign values in Rust | `unfilled` | | |
| `FFI-CK-PTR-VALID` | Rule | Check foreign pointers | `unfilled` | | |
| `FFI-INPUT-PTR` | Recommendation | Use raw pointer to encode pointers coming from the external language | `unfilled` | | |
| `FFI-CK-INPUT-REF-VALID` | Rule | Do not use unchecked foreign references | `unfilled` | | |
| `FFI-MARKEDFUNPTR` | Rule | Mark function pointer types in FFI as `extern` and `unsafe` | `unfilled` | | |
| `FFI-CKFUNPTR` | Rule | Check foreign function pointers | `unfilled` | | |
| `FFI-NOENUM` | Rule | Do not use incoming Rust `enum` at FFI boundary | `unfilled` | | |
| `FFI-R-OPAQUE` | Recommendation | Use dedicated Rust types for foreign opaque types | `unfilled` | | |
| `FFI-C-OPAQUE` | Recommendation | Use incomplete C/C++ `struct` pointers to make type opaque | `unfilled` | | |
| `FFI-CK-REF-MODEL` | Rule | Preservation of Rust's memory model when transferring indirections at its boundary | `unfilled` | | |
| `FFI-MEM-NODROP` | Rule | Do not use types that implement `Drop` at FFI boundary | `unfilled` | | |
| `FFI-MEM-OWNER` | Rule | Ensure clear data ownership in FFI | `unfilled` | | |
| `FFI-MEM-WRAPPING` | Recommendation | Wrap foreign data in memory-releasing wrapper | `unfilled` | | |
| `FFI-NOPANIC` | Recommendation | Handle `panic!` correctly in FFI | `unfilled` | | |
| `FFI-CAPI` | Rule | Expose dedicated C-compatible API only | `unfilled` | | |

### UNSAFE — umbrella (1 rule)

| Rule (English ID) | Type | Title | Status | Evidence | Notes |
|---|---|---|---|---|---|
| `UNSAFE-NOUB` | Rule | No Undefined Behavior | `unfilled` | | |

## Documented Deviations

(Empty in M1. M2 populates this section with each `waived` row's compensating control.)

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

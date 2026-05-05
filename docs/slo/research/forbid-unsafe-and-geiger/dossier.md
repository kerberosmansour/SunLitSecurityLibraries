---
name: forbid-unsafe-and-geiger
researched: 2026-05-05
incomplete: false
---

# Research Dossier — `forbid(unsafe_code)` + `cargo-geiger` for SunLit

## Lint behaviour — `forbid(unsafe_code)` vs `deny(unsafe_code)`

`unsafe_code` is an allow-by-default rustc lint covering `unsafe` blocks/`fn`s, `no_mangle`, `export_name`, `link_section`. `forbid` differs from `deny`: once set to `forbid`, no inner `#[allow]`/`#[deny]` can lower it; only `--cap-lints` softens it. `deny` is locally overridable. Rust 1.83+ behaviour is unchanged from 1.0. Where `forbid` is not total: `#[allow_internal_unsafe]` macros (used by some std macros) bypass it (rust-lang/rust#56768, still open). For a normal third-party `proc_macro_derive`, `forbid` checks the *expanded* TokenStream in the consumer crate, so any literal `unsafe` token in expansion is rejected as if source-typed.

## Macro expansion and `forbid` — concrete cases

| Macro / crate | Expansion contains `unsafe`? | Effect on `forbid(unsafe_code)` | Source |
|---|---|---|---|
| `serde_derive` | No — pure visitor pattern. | Compatible. axum/rustls/tower use it under forbid. | serde_derive/src/lib.rs |
| `thiserror::Error` | No — no `unsafe` token in `expand.rs`. | Compatible. | thiserror/impl/src/expand.rs |
| `tokio::pin!` (macro_rules) | Yes — `unsafe { Pin::new_unchecked(&mut $x) }`. | **Breaks `forbid(unsafe_code)` at the call site.** Substitute `pin-project-lite`. | docs.rs/tokio/.../macros/pin.rs.html |
| `pin-project` (`#[pin_project]`) | Internally yes; in the typical path the *consumer-side expansion* contains no `unsafe`. With `UnsafeUnpin`, an `unsafe impl` is emitted (intentional, so geiger sees it). | Compatible without `UnsafeUnpin`; breaks forbid with it. | taiki-e/pin-project PR #18 |
| `pin-project-lite` (`pin_project!`) | Yes inside macro body. | Empirically *compatible* — axum/tower (both forbid) depend on it; unsafe is hygienic to lite's own crate. | docs.rs/pin-project-lite |
| `tracing::instrument` | No — wraps via safe `Span` API. | Compatible. | docs.rs/tracing |
| `axum-macros` (`#[derive(FromRequest)]`) | No. | Compatible — axum itself sets forbid. | github.com/tokio-rs/axum |
| `#[allow_internal_unsafe]` std macros | Yes; exempt from forbid by design. | Bypasses forbid (rust-lang/rust#56768). | rust-lang/rust#56768 |

## `cargo-geiger` — current status

**Verdict: active but partial (compat-tracking).** `geiger-rs/cargo-geiger` shipped v0.13.0 on 2025-08-31 (Rust 1.89) and v0.12.0 on 2025-04-10 (Cargo 0.86); 1,005 commits, 43 open issues, 9 open PRs, live CI through 2025–2026. Recent releases are dependency bumps and compiler-compat fixes, not features; the v0.13.0 milestone (due 2026-01-01) was 8% complete at access. Recommended workspace invocation: `cargo geiger --workspace --all-features --output-format Json` from the workspace root, with a parallel ASCII run for the README. `--all-features` is the conservative metric; `--no-default-features` is at most a delta indicator. The CLI (`cargo-geiger/src/cli.rs`) confirms native flag support.

## Successors / alternatives

| Tool | Measures | Maintenance | URL |
|---|---|---|---|
| `cargo-geiger` (incumbent) | `unsafe` token counts, transitive, with safe/unsafe ratios. | Active, partial. | github.com/geiger-rs/cargo-geiger |
| `cargo-indicate` | Trustfall/GraphQL queries over the dep graph; consumes geiger facts. | Active 2024–2025; complementary, not a drop-in replacement. | Volvo Cars Engineering writeup |
| `safety-dance` (rust-secure-code WG) | Curated catalog of audited / forbid-converted crates. | WG-maintained reference, not a CLI. | github.com/rust-secure-code/safety-dance |
| Hand-rolled `rg '\bunsafe\b'` over `cargo metadata` | Raw count of literal `unsafe` tokens. | Trivial fallback if geiger ever fails to compile. | n/a |

For SunLit, **stay on `cargo-geiger`** while monitoring the v0.13.0 milestone; keep a grep-fallback script ready. `cargo-indicate` is not a substitute — it consumes geiger.

## Real-world `forbid(unsafe_code)` adopters

| Crate / project | `forbid(unsafe_code)`? | Geiger number published? | URL |
|---|---|---|---|
| `rustls` | Yes — `#![forbid(unsafe_code, unused_must_use)]` at root. | No badge; CI uses cargo-audit/miri/fuzz/semver, not cargo-geiger. | rustls/src/lib.rs |
| `axum` (top-level crate) | Yes — README states explicitly. | Not numeric; the forbid attribute *is* the metric. | github.com/tokio-rs/axum |
| `tower` family | Yes — `#![forbid(unsafe_code)]` across all four published crates. | Not published. | tower/src/lib.rs |
| `hyper` | **No** — counter-example; uses `unsafe` for HTTP perf paths. | n/a | hyperium/hyper src/lib.rs |
| `serde` (core) | **No** — counter-example; some `unsafe` in core conversions. | n/a | serde/src/lib.rs |

Pattern: TLS / service / extractor crates commit to `forbid`; protocol-engine / serde-core crates take `deny` + named allow. SunLit's surface aligns with the first cluster.

## Tooling / CI patterns

| Project | CI step | Advisory or blocking? | URL |
|---|---|---|---|
| rustls | `.github/workflows/build.yml` — cargo-audit, clippy, miri, fuzz, external-types, semver. **No cargo-geiger.** | n/a | rustls build.yml |
| axum | clippy + tests; forbid enforced at compile time. | Blocking (compile-time). | github.com/tokio-rs/axum |
| cargo-geiger (own CI) | `cargo install --locked cargo-geiger`; `cargo geiger`. | Advisory in dogfood. | geiger-rs/cargo-geiger CI |
| Common pattern | `taiki-e/install-action@v2` or `baptiste0928/cargo-install@v3` to fetch prebuilt binary; `cargo geiger --output-format Json --workspace --all-features > geiger.json`; upload artifact. | Advisory, then promote once threshold calibrated. | rust-cargo-install action |

## Regulatory / certification angle

- **ANSSI Rust guide** — rules `LANG-UNSAFE` and `LANG-UNSAFE-ENCP` (Secure Rust Guidelines, "unsafe/generalities") **explicitly require** `#![forbid(unsafe_code)]` at the crate root: *"With the exception of these cases, `#![forbid(unsafe_code)]` must appear in the crate root … to generate compilation errors if `unsafe` is used in the code base."* Phrased `must`, not `should`. `UNSAFE-NOUB` requires no UB on safe-API entry; `LANG-UNSAFE-ENCP` requires encapsulation of unavoidable unsafe.
- **IEC 62443 / FedRAMP** — Neither names `forbid(unsafe_code)` as a control. FedRAMP (under FedRAMP 20x) accepts memory-safety arguments under SC-39 / SI-16-style controls; vendors may cite `forbid(unsafe_code)` + cargo-geiger output as supporting evidence in an SSP, but the language is non-normative. IEC 62443-4-1 (Secure Development Lifecycle) requires documented secure-coding practices — `forbid(unsafe_code)` plus a geiger-budget runbook satisfies the intent.
- **Industry framing** — Pictor.us "Rust is DO-178C Certifiable" and DirectDefense's memory-safety assessment treat `forbid(unsafe_code)` as the de facto memory-safety attestation in the Rust ecosystem.

## Open questions that research did not answer

- **Does `forbid(unsafe_code)` in the consumer crate reject unsafe emitted by a `macro_rules!` defined in a *different* crate?** Empirically pin-project-lite works inside axum/tower, so hygiene shields it — but the rustc reference does not state this contract; Rust-internals #14107 frames it as a known gap. Known *risk*, not a blocker today.
- **What threshold should M3 set?** No field-current public baseline was located for comparable security-crate workspaces. The runbook must derive the threshold from the first measured value plus documented headroom.
- **Will `cargo-geiger` survive Rust 2027 / cargo-resolver-v3?** v0.13.0 commits only through Rust 1.89; longer horizons require monitoring.

# Sources — `forbid-unsafe-and-geiger`

All URLs accessed 2026-05-05.

## rustc reference and lint behaviour

- [Lint levels — The rustc book](https://doc.rust-lang.org/rustc/lints/levels.html) — Authoritative description of `forbid` vs `deny`: forbid cannot be lowered by inner attribute (only `--cap-lints` can cap it).
- [Allowed-by-default lints — `unsafe_code`](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html) — Confirms `unsafe_code` is allow-by-default; catches `unsafe`, `no_mangle`, `export_name`, `link_section`.
- [`#[allow_internal_unsafe]` evades `#![forbid(unsafe_code)]` — rust-lang/rust#56768](https://github.com/rust-lang/rust/issues/56768) — Open issue documenting that macros marked `allow_internal_unsafe` (a built-in / internal attribute) can hide `unsafe` from `forbid`. Still open as of 2026-05-05.
- [Hidden unsafe due to unintentionally abusable macros — Rust internals](https://internals.rust-lang.org/t/hidden-unsafe-due-to-unintentionally-abusable-macros-and-include/14107) — Discussion confirming `#![forbid(unsafe_code)]` does not catch unsafe operations hidden in macros expanded from another crate.
- [Lints about `unsafe {}` blocks propagate inside macros — rust-lang/rust#74838](https://github.com/rust-lang/rust/issues/74838) — Tracks how `unsafe_code` lint propagation behaves through macro hygiene boundaries.

## `cargo-geiger` maintenance status

- [geiger-rs/cargo-geiger — README](https://github.com/geiger-rs/cargo-geiger) — Repo description, install instructions, ~1.6k stars, 1,005 commits on master, 43 open issues, 9 open PRs at access time.
- [cargo-geiger Releases](https://github.com/geiger-rs/cargo-geiger/releases) — Most recent: v0.13.0 (2025-08-31, Rust 1.89 compatibility); v0.12.0 (2025-04-10, Cargo 0.86).
- [cargo-geiger CI workflow runs](https://github.com/geiger-rs/cargo-geiger/actions/workflows/ci.yml) — Active CI runs through 2025-2026 indicate ongoing maintenance.
- [cargo-geiger src/scan/default.rs](https://github.com/geiger-rs/cargo-geiger/blob/master/cargo-geiger/src/scan/default.rs) — Source confirming `--all-features` and `--no-default-features` flag handling.
- [cargo-geiger src/cli.rs](https://github.com/geiger-rs/cargo-geiger/blob/master/cargo-geiger/src/cli.rs) — CLI definition for feature flag handling, JSON output, workspace scan.

## Successors / alternatives

- [Comparing Rust supply chain safety tools — LogRocket (2022-05-10)](https://blog.logrocket.com/comparing-rust-supply-chain-safety-tools/) — Surveys cargo-audit, cargo-deny, cargo-outdated, cargo-geiger, cargo-crev. No newer successor listed for unsafe-counting.
- [Looking for Bad Apples in Rust Dependency Trees — Volvo Cars Engineering / Medium](https://medium.com/volvo-cars-engineering/looking-for-bad-apples-in-rust-dependency-trees-using-graphql-and-trustfall-cb88b835f652) — Uses `cargo-indicate` (Trustfall over the dep graph) which can include geiger-derived facts; positions itself as complementary, not replacement.
- [rust-secure-code/safety-dance](https://github.com/rust-secure-code/safety-dance) — Working group repo: documents the practice of replacing transitive `unsafe` and recommends `#![forbid(unsafe_code)]` for cleaned crates.
- [cargo-audit (rustsec/rustsec)](https://github.com/rustsec/rustsec) — RustSec advisory tooling (CVE-style); orthogonal concern, not a geiger replacement.

## Macro expansion sources

- [pin_project source / docs.rs](https://docs.rs/pin-project/latest/pin_project/) — Confirms `pin-project` encapsulates unsafe internally and exposes `UnsafeUnpin` (`unsafe` trait) for the case where consumer-provided unsafe is needed. Maintainer text on docs page: pin-projection is "completely safe unless you write other unsafe code."
- [taiki-e/pin-project PR #18 — Replace `unsafe_project` with safe `pin_projectable`](https://github.com/taiki-e/pin-project/pull/18) — Notes: "Using the actual unsafe keyword allows for proper integration with the unsafe_code lint, and tools cargo geiger." Implies pin-project's expansion is detected by `unsafe_code`.
- [pin_project_lite docs](https://docs.rs/pin-project-lite/latest/pin_project_lite/) — Macro_rules-based; its expansion contains `unsafe`, but `pin-project-lite` is widely used in `#![forbid(unsafe_code)]` crates including axum.
- [tokio macros/pin.rs source](https://docs.rs/tokio/latest/src/tokio/macros/pin.rs.html) — Source: `tokio::pin!` expands to `unsafe { $crate::macros::support::Pin::new_unchecked(&mut $x) }`.
- [Unsafe macros and `#![forbid(unsafe_code)]` — pin-utils#2](https://github.com/rust-lang/pin-utils/issues/2) — Long-standing issue about `unsafe_pinned!` macro hiding `unsafe` blocks behind a safe-looking macro call.
- [serde_derive/src/lib.rs](https://github.com/serde-rs/serde/blob/master/serde_derive/src/lib.rs) — No `unsafe` keyword in proc-macro entry; proc-macro emits derived `impl Serialize/Deserialize` blocks that are pure safe code.
- [thiserror impl/src/expand.rs](https://github.com/dtolnay/thiserror/blob/master/impl/src/expand.rs) — Generated impls contain no `unsafe` keyword; verified by source grep.
- [rust-lang/rust-clippy#15137 — `unsafe_derive_deserialize`: do not consider `pin!()` as `unsafe`](https://github.com/rust-lang/rust-clippy/pull/15137) — 2025-2026 era PR confirming `pin!()` macro is currently treated as unsafe-using by clippy heuristics.

## Real-world `forbid(unsafe_code)` adopters

- [rustls/rustls — rustls/src/lib.rs](https://github.com/rustls/rustls/blob/main/rustls/src/lib.rs) — Top of crate root: `#![forbid(unsafe_code, unused_must_use)]`.
- [tokio-rs/axum README](https://github.com/tokio-rs/axum) — "This crate uses `#![forbid(unsafe_code)]` to ensure everything is implemented in 100% safe Rust."
- [tower-rs/tower — tower/src/lib.rs](https://github.com/tower-rs/tower/blob/master/tower/src/lib.rs) — `#![forbid(unsafe_code)]` set at crate root; mirrored across `tower-service`, `tower-layer`, `tower-http`.
- [tokio-rs/axum — axum-core/src/lib.rs](https://github.com/tokio-rs/axum/blob/main/axum-core/src/lib.rs) — Note: `axum-core` does *not* set `forbid(unsafe_code)` in its lib root at access time; only the top-level `axum` crate does.
- [hyperium/hyper — src/lib.rs](https://github.com/hyperium/hyper/blob/master/src/lib.rs) — Does *not* set `forbid(unsafe_code)`; uses `deny(missing_docs)` etc. only. Hyper does contain `unsafe` for performance.
- [serde-rs/serde — serde/src/lib.rs](https://github.com/serde-rs/serde/blob/master/serde/src/lib.rs) — Does *not* set `forbid(unsafe_code)`; serde core uses unchecked conversions in places.

## CI patterns

- [rustls build.yml workflow](https://github.com/rustls/rustls/blob/main/.github/workflows/build.yml) — Does NOT run cargo-geiger. Uses cargo-audit, clippy, miri, fuzz, semver-checks, external-types.
- [rust-cargo-install GitHub Action](https://github.com/marketplace/actions/rust-cargo-install) — Standard prebuilt-binary installer used to add cargo-geiger to a workflow without compile time hit.
- [BamPeers/rust-ci-github-actions-workflow](https://github.com/BamPeers/rust-ci-github-actions-workflow) — Template Rust CI workflow; documents standard install pattern for tooling like cargo-geiger.

## Regulatory / certification

- [ANSSI Secure Rust Guidelines — checklist](https://anssi-fr.github.io/rust-guide/checklist.html) — Lists rules `LANG-UNSAFE`, `UNSAFE-NOUB`, `LANG-UNSAFE-ENCP`.
- [ANSSI rust-guide source — unsafe/generalities.md](https://anssi-fr.github.io/rust-guide/unsafe/generalities.html) — Quote: "With the exception of these cases, `#![forbid(unsafe_code)]` must appear in the crate root … to generate compilation errors if `unsafe` is used in the code base." This is a `must`, not a `should`.
- [ANSSI-FR/rust-guide#10 — Forbid unsafe code](https://github.com/ANSSI-FR/rust-guide/issues/10) — Issue tracking incorporation of `forbid(unsafe_code)` recommendation; the rule is now in the published guide.
- [Assessing Memory Safety in Programming Languages — DirectDefense](https://www.directdefense.com/assessing-memory-safety-in-programming-languages-like-rust-and-go/) — General industry framing of memory-safety attestation language.
- [FedRAMP overview — Anchore](https://anchore.com/fedramp/fedramp-overview/) — FedRAMP 20x modernization context; FedRAMP itself does not name `forbid(unsafe_code)` as a control but accepts memory-safety arguments under SC-39 / SI-16-style controls.
- [Rust is DO-178C Certifiable — Pictor.us blog](https://blog.pictor.us/rust-is-do-178-certifiable/) — Industry blog on safety-critical certification posture for Rust; relevant context for SunLit's certification framing.

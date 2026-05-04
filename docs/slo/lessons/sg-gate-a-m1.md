# Lessons Learned — sg-gate-a Milestone 1

## What changed
- `secure_boundary` gained an `actix-web` Cargo feature. The existing `axum` path became explicit (and remains default). Three Actix-web 4 adapters shipped: `SecureJson<T>` (as `FromRequest`), `SecurityHeadersTransform` (as `Transform`), `FetchMetadataTransform` (as `Transform`).
- Four framework-neutral helpers were extracted so axum and Actix share the real logic: `extract::validate_json_bytes`, `extract::validate_parsed`, `headers::security_header_pairs`, `fetch_metadata::classify`.
- `--no-default-features` still builds (framework-neutral subset only). Both features compose on `--features "axum actix-web"`.

## Design decisions and why
- **Framework-neutral helpers return values, not mutate types.** Originally I planned a single `apply_security_headers(&mut HeaderMap, ...)`. Actix-http uses `http 0.2.x` internally while this crate uses `http 1.x`, so `&mut HeaderMap` would have been ambiguous. Returning `Vec<(HeaderName, HeaderValue)>` sidesteps the version divergence — each framework inserts into its own map. If we ever share more logic, the pair-iterator pattern scales better than trait-based abstraction.
- **Actix `FromRequest` uses a local newtype for rejection mapping.** `BoundaryRejection` from this crate does not implement `actix_web::ResponseError`. Making it do so would couple the framework-neutral error type to actix-web. Wrapping it in a private `BoundaryRejectionError(BoundaryRejection)` inside the adapter module keeps the core unopinionated.
- **Method conversion via bytes.** `actix-web 4`'s `req.method()` returns `http::Method` from the 0.2 version; our `classify` takes `http::Method` from 1.x. Converting through `as_str().as_bytes()` is slower but robust against either version of `http` changing.

## Mistakes made
- First draft of the parity test used a generic `fn app() -> App<impl ServiceFactory<..., Response = ServiceResponse<BoxBody>, ...>>` helper. The `FetchMetadataTransform` wraps responses in `EitherBody<B, BoxBody>`, so the response type is `ServiceResponse<EitherBody<BoxBody, BoxBody>>` and the helper type-signature mismatched. Fix: inlined `App::new()...` at each call site (or promoted to a `macro_rules!`). Takeaway: Actix response types through `.wrap()` chains are fragile to annotate; prefer inlining for tests.
- Forgot `use actix_web::HttpMessage;` in the headers test (needed for `req.extensions()`). Took one compile error to notice.

## Root causes
- `http` crate has two major versions in widespread use (0.2 and 1.x). `actix-web 4` is still on 0.2 as of v4.13. Any code that crosses the actix/http boundary must convert — either explicitly (what we did) or by pinning a compatible version workspace-wide (more invasive).
- Actix doesn't re-export `HttpMessage` at the crate root. It's required for `.extensions()`/`.extensions_mut()` on both `HttpRequest` and `ServiceRequest`.

## What was harder than expected
- Rustdoc intra-doc link resolution from module-level `//!` comments. Bare `[`X`]` where X is a submodule type failed even with `pub use X;` in scope. Solved by using explicit link syntax: `[`X`](crate::a::b::X)`.
- Reconciling which modules need to be feature-gated. The mental model that worked: "everything that imports axum, tower, or tower-http goes behind `#[cfg(feature = "axum")]`." For new shared helpers: `#[cfg(any(feature = "axum", feature = "actix-web"))]`.

## Naming conventions established
- **Adapter module**: `src/actix/` with `mod.rs`, `extract.rs`, `headers.rs`, `fetch_metadata.rs`. M2 follows the same pattern.
- **Transform naming**: `XxxTransform` for the builder + `XxxMiddleware<S>` for the wrapped service (Actix's idiom, not tower's). Behaves like a tower `Layer` + `Service` pair.
- **Shared helpers**: `pub(crate) fn verb_noun` (`validate_json_bytes`, `security_header_pairs`, `classify`, `emit_cross_site_block`).
- **Test file prefix**: `sg_gate_a_actix_<feature>.rs` for Actix-only, `sg_gate_a_parity_<feature>.rs` for cross-framework parity, `e2e_sg_gate_a_m<N>.rs` for E2E.

## Test patterns that worked well
- **Cross-framework parity tests are load-bearing.** `parity_secure_json_*` and `parity_security_headers_default_set_match` each assert axum-vs-actix outcome identity on the same input. Caught a real issue pre-implementation (the HeaderMap type divergence).
- **`#![cfg(feature = "actix-web")]` at the top of an integration test file** — then the test is implicitly skipped under `--no-default-features` or `--features axum`, and compiled + run under `--features actix-web`. No runtime skipping needed.
- **Inline `App::new()` in each test** beat abstracting a helper with a generic return type.

## Missing tests that should exist now
- Parity test for CSP nonce presence (we assert nonce is inserted on Actix, but we don't yet assert both frameworks put the nonce in the same CSP directive position). If M2 or later touches CSP, add.
- Parity for `allow_missing_headers(false)` (the strict fetch-metadata mode). Currently covered per-framework but not as parity.

## Rules for the next milestone (M2)
- Follow the same pattern: keep the config type (`AuthzLayer<A>`) and any trait usage framework-neutral; lift the enforcement logic (`enforce::run_check`) out of the axum-only module; gate axum impls on `#[cfg(feature = "axum")]`; build Actix `AuthzTransform` using the shared helper.
- Actix `Transform` for `AuthzLayer` will have the same `EitherBody<B, BoxBody>` return-type pattern as `FetchMetadataTransform`. Reuse that idiom.
- For `impl ResponseError for AppError` in `secure_errors`: use a local newtype if `AppError` should stay framework-neutral. If we decide to expose `impl actix_web::ResponseError for AppError` directly (one of Actix's expected patterns), that's acceptable too — but weighs `secure_errors` with actix-web knowledge. Choose once and stick to it across M2.
- Every new public item gets a rustdoc `# Examples` doctest. No broken intra-doc links.

## Template improvements suggested
- The v3 runbook template's "New dependencies allowed" field should support a sub-bullet for "introduces a major-version-skew concern" — for this milestone, `actix-http 3.x` pulls `http 0.2` while the crate uses `http 1.x`. Had to work around at the adapter boundary. Future milestones that integrate other old-ecosystem crates will hit this again; calling it out explicitly in the contract would reduce surprise.

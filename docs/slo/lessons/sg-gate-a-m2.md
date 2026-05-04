# Lessons Learned — sg-gate-a Milestone 2

## What changed
- `secure_authz` gained an `actix-web` Cargo feature alongside the (default) `axum`. New `src/actix/middleware.rs` ships `AuthzTransform` + `AuthzMiddleware`. Framework-neutral enforcement logic lifted into `src/enforce.rs` (new `run_check`, `ObligationFulfillment`, `EnforceOutcome`).
- `secure_errors` gained an `actix-web` feature. New `src/actix.rs` provides `impl actix_web::ResponseError for AppError` routed through the single-source-of-truth `http::into_response_parts`.
- `ObligationFulfillment` moved from `secure_authz::middleware` (axum-only) to `secure_authz::enforce` (framework-neutral). No downstream consumers broke (verified via grep).
- Both crates now compose with `"axum actix-web"`, and `--no-default-features` still builds.

## Design decisions and why
- **Direct `impl ResponseError for AppError` rather than a wrapper newtype.** M1 used a local `BoundaryRejectionError(BoundaryRejection)` newtype. For M2 we chose direct impl: handlers expect `Result<_, AppError>` ergonomics, and `secure_errors` already couples to axum for `IntoResponse`, so the symmetrical coupling to Actix (feature-gated) is consistent. Revisit if we decide to reduce coupling in both frameworks.
- **`Rc<S>` for the actix inner service.** Actix middleware `Service::call` takes `&self`, so the inner service must be shared across the returned future. Cloning an `Rc<S>` is the canonical pattern (see actix's own middleware implementations). `Arc<S>` would also work but `Rc` matches actix's single-threaded-runtime conventions.
- **Deny synthesises a fresh `HttpResponse` instead of calling and discarding the inner future.** Simpler and avoids consuming `ServiceRequest` prematurely. The inner handler is never invoked on Deny, so side effects don't fire.
- **`enforce::run_check` takes `identity: Option<&AuthenticatedIdentity>`** rather than extracting from a request-abstraction trait. Keeps the helper framework-free and testable in isolation.

## Mistakes made
- First draft of `AuthzMiddleware::call` tried to call `self.service.call(req)` synchronously before awaiting the authz decision, then drop the future on Deny. That works semantically (unpolled futures don't execute) but requires consuming the `ServiceRequest` up front — which means on Deny we can't build a 403 response from `req` anymore. Switched to the `Rc<S>` + call-inside-async-block pattern; the authz decision runs first, and only Allow reaches `service.call`.
- Initial test file used an API that didn't exist: `Action::from_str_unchecked`, `AuthenticatedIdentity` fields I made up (`auth_level`, `token_issued_at`, `token_expires_at`). Fix: re-read the real type definitions before writing tests. M1 worked because I'd already read those files; M2 I assumed I remembered from context. Rule: always re-read signatures before drafting test fixtures.

## Root causes
- Actix-web 4's still-on-`http = 0.2` ecosystem doesn't affect `secure_authz` (we don't insert headers in the authz middleware), but would hit us again if we ever needed to write response headers here. If M3/M4 add anything that sets headers on Actix responses, expect the same conversion dance from M1.
- `secure_authz::middleware::ObligationFulfillment` was the pre-existing name. Moving to `enforce::ObligationFulfillment` without a backward-compat re-export was safe only because grep confirmed no external consumers. If we'd been publishing semver-stable, the deprecation would have been mandatory.

## What was harder than expected
- Getting the `Transform` type parameters right for `AuthzTransform<A>` where `A: Authorizer`. Needed `+ Send + Sync + 'static` bounds matching axum's `AuthzLayer`, and the `Service` impl's where-clauses kept needing adjustments until the rustc error messages converged.
- Parity test scaffolding: `secure_authz::middleware::AuthzLayer` requires `A: Clone` for its tower integration. Had to add `#[derive(Clone)]` to the parity-test `FixedAuthorizer` even though the actix adapter doesn't need it. Takeaway: when writing parity tests, start with the union of requirements from both framework-specific impls.

## Naming conventions established
- `enforce::run_check` — framework-neutral async function name for "run the authz check once". If other crates need similar framework-neutral helpers, use `enforce::verb_phrase`.
- `EnforceOutcome` — a two-variant enum rather than `bool` for allow/deny. Caller clarity > brevity.
- `AuthzTransform` / `AuthzMiddleware` — Actix naming. Rust tower uses `Layer`/`Service`; Actix uses `Transform`/"middleware". Follow the framework's idiom, don't force one language onto both.

## Test patterns that worked well
- **Parity tests as a black-box assertion over the public API.** Same input in, same output out — regardless of which framework processed it. Caught the potential drift of `AppError` → HTTP status mapping across frameworks by asserting byte-identical JSON.
- **Macro for repetitive table-driven tests** (`assert_mapping!` in `sg_gate_a_actix_errors.rs`). Nine variants × similar assertions would be noisy as individual functions; the macro keeps each test focused on its variant-specific expectations.

## Missing tests that should exist now
- Actix-specific: a test confirming `AuthzTransform` works when composed with `SecurityHeadersTransform` (both security headers AND authz denial applied). Currently tested separately; the E2E will cover it implicitly in M4.
- Obligation fulfillment parity across axum vs Actix — right now only happy path and deny are tested for parity. If M4 time permits, add.

## Rules for the next milestone (M3 — SafeUrl CIDRs)
- No framework code; this is pure type-level validation. Don't touch Cargo.toml, don't touch lib.rs (except rustdoc updates). The variant-analysis test file is the main deliverable — one `#[test]` per CIDR.
- No refactor. Extend `is_private_ipv4` and `is_private_ipv6` with four new branches. That's it.
- Rustdoc explicitly lists all 12 CIDRs. Don't say "private IPs"; enumerate.

## Template improvements suggested
- The runbook's Contract Block could benefit from a "cross-framework parity expectation" line for milestones adding framework adapters. M2 had parity as an implicit rule (established in M1 lessons); making it explicit per-milestone would reduce risk of silent drift.

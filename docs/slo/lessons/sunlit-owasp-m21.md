# Lessons Learned — sunlit-owasp Milestone 21

## What changed
- Added `cors.rs` with `secure_cors_defaults()` and `SecureCorsBuilder`
- Added `fetch_metadata.rs` with `FetchMetadataLayer`
- Extended `SecurityHeadersLayer` with per-request `CspNonce` support and configurable `Permissions-Policy`
- Added BDD and E2E tests for CORS, Fetch Metadata, CSP nonce generation, and browser-header compatibility
- Updated architecture, README, developer guides, threat model, and attack-tree docs for the new browser security controls

## Design decisions and why
- **Compose, don't wrap** — used `tower_http::cors::CorsLayer` directly via a secure helper and small builder rather than introducing a bespoke CORS abstraction
- **Deny-all by default** — `secure_cors_defaults()` returns `CorsLayer::new()` with no allowed origins, methods, or headers until the caller explicitly opts in
- **Opt-in CSP nonce generation** — `.with_csp_nonce()` preserves backward compatibility for existing code and tests that assert exact default CSP values
- **Nonce generation via `Uuid::new_v4()` + base64** — gives 128 bits of randomness without bringing in an additional RNG dependency
- **Backward-compatible Fetch Metadata policy** — missing `Sec-Fetch-*` headers are allowed for older browsers, while unsafe `cross-site` API requests are blocked unless they are safe top-level navigations

## Mistakes made
- Initial `clippy` pass failed due to redundant `#[must_use]` annotations on builder methods and a redundant async block
- Final `cargo doc --no-deps --workspace` run surfaced pre-existing broken intra-doc links in `secure_data` and `safe_types`

## Root causes
- `CorsLayer` and `SecureCorsBuilder` were already `#[must_use]`, so method-level annotations triggered `clippy::double_must_use`
- Rustdoc treats unresolved feature-gated or ambiguous intra-doc links as warnings, and some older comments used link syntax where plain code formatting was safer

## What was harder than expected
- Balancing CSP nonce generation with backward compatibility for existing `SecurityHeadersLayer` tests that compare the exact default CSP string

## Naming conventions established
- Module names: `cors.rs`, `fetch_metadata.rs`
- Public helper/builder names: `secure_cors_defaults()`, `SecureCorsBuilder`
- Nonce type: `CspNonce`
- Test files: `sunlit_owasp_cors.rs`, `sunlit_owasp_fetch_meta.rs`, `e2e_sunlit_owasp_m21.rs`

## Test patterns that worked well
- Using real `axum::Router` + `tower::ServiceExt::oneshot` for both BDD and E2E validation
- Verifying nonce uniqueness across sequential requests instead of mocking randomness
- Asserting the **absence** of `Access-Control-Allow-Origin` for deny-all and disallowed-origin cases

## Missing tests that should exist now
- Route-level example showing a deliberately cross-origin API composed with a separate Fetch Metadata policy
- Preflight coverage for explicitly allowlisted custom request headers
- A custom-CSP `{nonce}` placeholder round-trip test

## Rules for the next milestone
- M22 should preserve the existing `AuditEmitter` API and keep new sink integrations behind feature flags
- Run `cargo doc --no-deps --workspace` earlier in the milestone to catch rustdoc issues before the final exit gate

## Template improvements suggested
- Add `cargo doc --no-deps --workspace` to the explicit pre-flight baseline checks so rustdoc issues are caught before exit validation

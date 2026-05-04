# Production deployment checklist — SunLitSecurityLibraries

> Copy-paste checklist for services adopting these libraries. Aim: every box ticked before a service opens its listener in production. Run through this once per service; rerun after any substantial change to service configuration or boot code.

## 1. Boot-time assertions

- [ ] **Call `secure_identity::assert_no_dev_identity_in_production(APP_ENV, has_dev_source)` in `main()`** before the listener starts. Panic on `Err`. A misconfigured production deploy fails closed instead of running with a bypass in place. See [example](../../crates/secure_identity/examples/production_boot.rs).
- [ ] **`APP_ENV` is explicitly set** in production environments (not unset, not `"dev"`). The helper only triggers on the exact string `"production"`.
- [ ] **`has_dev_source` is computed from your actual authenticator chain.** If your service does `if cfg!(feature = "dev")`, pass that. If you store authenticators in a `Vec`, probe each for a dev marker.

## 2. Outbound URL handling

- [ ] **All outbound URLs constructed from user input are validated via `SafeUrl::try_from`.** The 12-CIDR blocked set (see [SafeUrl guide](./safe-url-ssrf.md)) includes AWS IMDS (`169.254.0.0/16`), IPv6 link-local (`fe80::/10`), multicast, RFC 1918, and loopback.
- [ ] **Serde DTOs that carry URLs use `SafeUrl` as the field type.** Validation happens at `serde_json::from_slice` time — before your handler runs.
- [ ] **If you resolve DNS before connecting**, re-validate the resolved `IpAddr` with the same predicate. `SafeUrl` doesn't catch DNS rebinding; you need an in-resolver check.

## 3. Framework feature flags

- [ ] **Each crate that supports multiple frameworks has exactly one framework feature enabled.** Don't compile with `--no-default-features` in production unless you're intentionally using only the framework-neutral subset.
- [ ] **Sunlit Guardian / Actix services use `features = ["actix-web"]` + `default-features = false`.** The Actix path composes with axum but paying to compile both is waste.
- [ ] **CI gates the feature matrix.** The `feature-matrix` job in `.github/workflows/ci.yml` runs every (crate × feature) combination. If your downstream service extends the matrix, mirror it there too.

## 4. Authz coverage

- [ ] **Run `secure_authz::testing::assert_every_route_has_policy` in your service's CI.** See [example](../../crates/secure_authz/examples/route_coverage.rs). The helper flags routes that deny for every fixture — usually a missing-policy misconfiguration.
- [ ] **Fixtures cover every role/tenant pair you expect in production.** A coverage sweep with too few fixtures will have false-positive "unmapped" flags.
- [ ] **AuthzTransform / AuthzLayer installed on every route that requires authz.** Public endpoints (health, metrics) are excluded explicitly, not by omission.

## 5. Response-level hardening

- [ ] **`SecurityHeadersTransform` (Actix) or `SecurityHeadersLayer` (axum) wraps every user-facing route.** Outer-first on request so 4xx/5xx short-circuit responses still carry security headers.
- [ ] **`FetchMetadataTransform` / `FetchMetadataLayer` is installed for browser-facing routes.** Not needed for pure machine-to-machine APIs; the `allow_missing_headers` default preserves backward compat for older clients.
- [ ] **`ErrorMappingLayer` (axum) or `impl ResponseError for AppError` (actix via feature flag) is active.** Handlers return `Result<_, AppError>` and errors map through `http::into_response_parts`.

## 6. Supply-chain gates

- [ ] **Upstream `deny.toml` copied or fetched into downstream's CI.** See `SunLitSecurityLibraries/deny.toml`.
- [ ] **`cargo audit`, `cargo deny check`, `cargo vet` all pass on every PR.** The `supply-chain` CI job runs all three.
- [ ] **Extended dep tree vetted.** Adopting these libraries pulls axum / actix / tokio / serde / http / thiserror. Your `cargo vet` audit decisions should cover those.

## 7. Error body / leak prevention

- [ ] **No handler ever emits a raw error message to the wire.** Return `Err(AppError::...)` and let the three-layer error model produce a `PublicError` JSON body.
- [ ] **`BoundaryRejection::SsrfAttempt`, `::MalformedBody`, etc. are handled by the `SecureJson` extractor** — they return stable error codes, not the attacker's input.
- [ ] **Internal logs include `request_id` but never raw payloads.** Use `tracing` spans bound to request IDs; let `PublicError`'s `request_id` field flow to clients for support correlation.

## 8. Framework adapter drift

- [ ] **Cross-framework parity tests are present and pass** for any crate used on multiple frameworks in the same workspace. See `sg_gate_a_parity_*` for the canonical examples.
- [ ] **`cargo doc --workspace --no-deps --all-features` has zero warnings.** Enforced by the `rustdoc-warnings` CI job.

---

When every box above is checked: ship.

When any box is unchecked: treat it as a release-blocker unless you have a documented, approved exception signed off by security.

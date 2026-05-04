# Sunlit Guardian Gate A — completion notice

**Runbook**: [`docs/slo/completed/RUNBOOK-sunlit-guardian-gate-a.md`](./RUNBOOK-sunlit-guardian-gate-a.md)
**Status**: All 4 milestones `done` as of 2026-04-24.

---

## What Sunlit Guardian gets

The v4 feedback doc's Gate A asks are satisfied:

| Ask | Status | Where |
|---|---|---|
| **A1** — Actix-web 4 adapters for `SecureJson<T>`, `SecurityHeadersLayer`, `FetchMetadataLayer` | ✅ M1 | `secure_boundary` feature `actix-web` |
| **A1** — Actix-web 4 adapter for `AuthzLayer` | ✅ M2 | `secure_authz` feature `actix-web` (`AuthzTransform`) |
| **A1** — Actix-web 4 adapter for `ErrorMappingLayer` | ✅ M2 | `secure_errors` feature `actix-web` (`impl ResponseError for AppError`) |
| **A2** — `SafeUrl` blocked-CIDR verification + extension | ✅ M3 | All 12 CIDRs on the v3-K2 list rejected; per-CIDR regression tests |
| **A4** — Production-boot assert helper | ✅ M4 | `secure_identity::boot::assert_no_dev_identity_in_production` |
| **A5** — Route-policy coverage test helper | ✅ M4 | `secure_authz::testing::assert_every_route_has_policy` |
| **C1** — License posture reconciliation | ✅ M4 | All manifests `license = "MIT"`; README has an explicit License section |
| **C3** — `deny.toml` publication | ✅ M4 | Header comment + README link; file is copy-paste ready |

Deferred (explicitly out of Gate A scope):

- **C2** — HMAC key rotation pattern for `security_events` (deferred in feedback doc).
- `SecureQuery<T>` / `SecurePath<T>` Actix adapters — only `SecureJson<T>` asked.
- IPv4-mapped IPv6 detection in `SafeUrl`.
- DNS-rebinding revalidation at connect time.

## How to consume

### Workspace-wide git-rev pin

Add to Sunlit Guardian's root `Cargo.toml`:

```toml
[workspace.dependencies]
secure_boundary = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5", default-features = false, features = ["actix-web"] }
secure_authz    = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5", default-features = false, features = ["actix-web"] }
secure_errors   = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5", default-features = false, features = ["actix-web"] }
secure_identity = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5" }
security_core   = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5" }
security_events = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5" }
secure_data     = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5" }
secure_output   = { git = "https://github.com/kerberosmansour/SunLitSecurityLibraries", rev = "2a5018c4f3a2a742011f109b26ab034641385ca5" }
```

> The SHA above is the Gate A merge commit on `main` (PR #1, merged 2026-04-24). Sunlit Guardian can pin this commit immediately.

### Per-crate feature wiring

| Crate | Feature for SG | Effect |
|---|---|---|
| `secure_boundary` | `actix-web` | `SecureJson<T>` as `actix_web::FromRequest`; `SecurityHeadersTransform`, `FetchMetadataTransform` middleware |
| `secure_authz` | `actix-web` | `AuthzTransform` middleware |
| `secure_errors` | `actix-web` | `impl actix_web::ResponseError for AppError` |
| `secure_identity` | (none) | `boot::assert_no_dev_identity_in_production` always available |
| `security_core` | (none) | `AuthenticatedIdentity` + `IdentitySource` always available |

All feature flags are additive — `--features "axum actix-web"` works for any crate above that has the `axum` feature (all three framework-coupled crates do). Downstream services on axum keep their existing integration untouched.

### Production-boot wiring

```rust,ignore
use secure_identity::boot::assert_no_dev_identity_in_production;

let app_env = std::env::var("APP_ENV").unwrap_or_default();
let has_dev = has_any_dev_authenticator_registered(); // service-specific

if let Err(violation) = assert_no_dev_identity_in_production(&app_env, has_dev) {
    panic!("{violation}");
}
```

### CI coverage gate

```rust,ignore
#[test]
fn every_route_has_policy() {
    let authz = build_authorizer();
    let routes = enumerate_routes();
    let fixtures = fixture_subjects();
    assert_every_route_has_policy(&authz, &routes, &fixtures)
        .expect("route-policy coverage gap detected");
}
```

## Testing summary

- **Workspace tests**: 1126 passing, 0 failing.
- **New Gate A tests**: 81 (M1: 25 + M2: 27 + M3: 22 + M4: 10) + 20 E2E scenarios across `secure_smoke_service`.
- **Cross-framework parity tests**: 19 (M1: 7, M2: 12) — axum and Actix paths asserted byte-identical on the same inputs.
- **Doctests**: all crates clean; `cargo doc --workspace --no-deps --all-features` zero warnings.
- **Feature matrix**: 12 build+test combinations on every PR (CI `feature-matrix` job).
- **Supply chain**: `cargo audit` + `cargo deny check` + `cargo vet` all green on the extended dep tree.

## Handoff

Sunlit Guardian can now start `/slo-execute M1` of its v4 unified-migration runbook. Cite this completion doc (and the runbook) in the Sunlit Guardian v4 migration notes; pin the rev once the Gate A merge lands on `main`.

If any of the blocked-CIDR tests, authz parity tests, or error parity tests ever fail in downstream CI, the root cause is almost always in Sunlit Guardian's feature-flag wiring or upstream auth middleware order — not in these libraries. Start with [`docs/dev-guide/`](../../dev-guide/README.md) and the E2E tests as reference material.

Open issues upstream (this repo) for any bug or feature request; do not fork.

# SunLitSecurityLibraries — dev guide

Engineer- and security-agent-facing documentation for adopting these libraries in your service. Every page lists what you get, the minimal dependency/config, a copy-paste example backed by a runnable example file, common pitfalls, and cross-references.

## Framework adapter guides

- [`secure_boundary` on Actix-web 4](./secure_boundary-actix.md) — `SecureJson<T>`, `SecurityHeadersTransform`, `FetchMetadataTransform`.
- [`secure_authz` on Actix-web 4](./secure_authz-actix.md) — `AuthzTransform` middleware (identity-agnostic).
- [`secure_device_trust`](./secure-device-trust.md) — native-client bootstrap identity, client type/platform, attestation mode, and trust-tier decisions.
- [Native device-trust release gate](./native-device-trust-release-gate.md) — release blocking via ZeroTrustAuth external conformance.
- [`secure_errors` on Actix-web 4](./secure_errors-actix.md) — `AppError` → HTTP response via `impl ResponseError`.

The axum adapters are covered by the per-crate rustdoc and the workspace's [`ARCHITECTURE.md`](../../ARCHITECTURE.md).

## Topic guides

- [SSRF prevention with `SafeUrl`](./safe-url-ssrf.md) — the full 12-CIDR blocked set, what it does and doesn't cover, integration patterns (serde, direct).
- [Production deployment checklist](./production-checklist.md) — boot-time assertions, CI gates, SSRF, feature-flag hygiene for services shipping to prod.
- [Branch protection](./branch-protection.md) — live baseline, public-release target, and required checks for GitHub.
- [Release process](./release-process.md) — crates.io packaging order, Sigstore verification, and GitHub hardening checklist.
- [Static analysis](./static-analysis.md) — Semgrep Rust scanning now and CodeQL code scanning once the repo is public.

## How the examples stay honest

Every code block in a dev-guide page that is meant to compile is backed by one of:
- a `///` doctest on the public API being shown,
- a matching `examples/*.rs` file in the crate's `examples/` directory,
- an integration or E2E test that constructs the same code.

`cargo doc --workspace --no-deps --all-features` must build with zero warnings, enforced by CI.

## Reference material inside the crates

- Per-crate crate-level docs in `crates/*/src/lib.rs` (rendered as `cargo doc`).
- Per-type rustdoc with `/// # Examples` blocks that run as doctests.
- `ARCHITECTURE.md` and `THREAT_MODEL.md` at the repo root for the big picture.

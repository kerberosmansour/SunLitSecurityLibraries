# secure_reference_service

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Not published to crates.io** (`publish = false`). This crate is an in-tree reference axum service used for integration testing and as a worked example of how the workspace crates compose end-to-end.

## What it demonstrates

A small axum service wired with the full SunLit Security Libraries stack:

- **`secure_boundary`** — secure JSON extractors with four-stage validation, security headers, Fetch Metadata, and secure CORS.
- **`secure_errors`** — single-source-of-truth error mapping; every error response goes through `into_response_parts` so the wire shape is stable.
- **`secure_identity`** — JWT/OIDC authentication producing `AuthenticatedIdentity`.
- **`secure_authz`** — `AuthzLayer` enforcing deny-by-default policy on guarded routes.
- **`secure_data`** — secret/envelope-encryption primitives in handler logic.
- **`secure_output`** — context-aware encoders for response payloads.
- **`secure_network`** — TLS policy and pin validation utilities.
- **`security_events`** — structured audit events emitted alongside spans.
- **`resilience::ResilienceConfig`** — timeout budgeting and retry policy.

The library facade exposes `build_router(state, &resilience_config)` so integration tests can spin up the same stack the binary runs.

## Run locally

```bash
cargo run -p secure_reference_service
```

## Used by

- Workspace integration tests under `crates/secure_reference_service/tests/`.
- `Crate Packaging Preflight` and feature-matrix CI jobs as a smoke target.

## Links

- Workspace: <https://github.com/kerberosmansour/SunLitSecurityLibraries>
- Architecture overview: [ARCHITECTURE.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/ARCHITECTURE.md)

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

# secure_reference_service

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Not published to crates.io.** This crate is an in-tree reference service used for integration testing.

A reference axum service that demonstrates how the SunLit Security Libraries compose end-to-end:

- `secure_boundary` for input validation, secure extractors, and security headers.
- `secure_errors` for the single-source-of-truth error mapping.
- `secure_identity` + `secure_authz` for auth and policy.
- `secure_data`, `secure_output`, `secure_network`, `security_events` wired into request handlers.
- `resilience::ResilienceConfig` for timeout budgeting and retry policy.

The library facade in `lib.rs` exposes `build_router` so integration tests can spin up the same stack the binary runs.

## Run locally

```bash
cargo run -p secure_reference_service
```

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

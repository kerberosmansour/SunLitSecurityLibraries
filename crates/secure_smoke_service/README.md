# secure_smoke_service

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Not published to crates.io.** This crate is a verification microservice — not a demo, not a starter template.

A purpose-built axum (and optional actix-web) microservice with 50+ routes, each exercising a specific security control from the **SunLit Security Libraries** workspace. Used by the Dastardly DAST scan in CI to catch regressions in the boundary, output, identity, authz, data, network, resilience, and privacy controls.

## What it covers

- Input-validation routes (XSS reflect, SQLi check, etc.) — exercises `secure_boundary`.
- Output-encoding routes — exercises `secure_output`.
- Identity / authz routes — exercises `secure_identity` (incl. biometric) and `secure_authz`.
- Data-protection routes (mobile-storage features) — exercises `secure_data`.
- Network/transport routes — exercises `secure_network`.
- Resilience and privacy routes — exercises `secure_resilience` and `secure_privacy`.

## Run locally

```bash
cargo run -p secure_smoke_service
```

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

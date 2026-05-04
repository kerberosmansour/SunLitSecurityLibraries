# secure_data

[![crates.io](https://img.shields.io/crates/v/secure_data.svg)](https://crates.io/crates/secure_data)
[![docs.rs](https://docs.rs/secure_data/badge.svg)](https://docs.rs/secure_data)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Data protection, secrets management, and FIPS readiness (OWASP C8). Part of the **SunLit Security Libraries** workspace.

## What this crate gives you

- Typed secret wrappers that suppress `Debug`, `Display`, and default `Serialize` output.
- Pluggable `KeyProvider` abstraction with a `StaticDevKeyProvider` for tests.
- Envelope encryption/decryption via AES-256-GCM (FIPS-ready `aws-lc-rs` behind the `fips` feature).
- Key-ring lifecycle management with rotation and dual-read.
- Secret reference parsing — `vault://`, `kms://`, `env://`.
- `Zeroize` and `ReadOnce` memory helpers.
- Argon2id password hashing and verification (OWASP C2/C7).

## Feature flags

| Flag | Dependency | Purpose |
|---|---|---|
| `vault` | `reqwest` | HashiCorp Vault Transit key provider + KV secret resolution. |
| `aws-kms` | `aws-sdk-kms`, `aws-config` | AWS KMS `GenerateDataKey` / `Decrypt` provider. |
| `fips` | `aws-lc-rs` | FIPS 140-2/3 validated AEAD backend. |
| `password` | `argon2` | Argon2id password hashing and verification. |
| `azure-kv` | — | Azure Key Vault key provider (wrap/unwrap only). |
| `mobile-storage` | — | Mobile secure storage: `SensitiveBuffer`, `BackupExclusion`, `MobileStoragePolicy` (MASVS-STORAGE-1). |

All features are off by default. Enable with e.g. `cargo add secure_data --features vault,aws-kms,password`.

## Install

```toml
[dependencies]
secure_data = { version = "0.1", features = ["password"] }
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

# secure_data

[![crates.io](https://img.shields.io/crates/v/secure_data.svg)](https://crates.io/crates/secure_data)
[![docs.rs](https://docs.rs/secure_data/badge.svg)](https://docs.rs/secure_data)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Secrets management, envelope encryption, password hashing, and FIPS-ready cryptography (OWASP C8). Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

- You handle **secrets in-memory** (API tokens, DB passwords, signing keys) and want types that suppress `Debug`, `Display`, and default `Serialize` and that zero on drop.
- You need **envelope encryption** with a pluggable KMS (Vault, AWS KMS, Azure Key Vault, or a static dev key).
- You need **Argon2id password hashing** (OWASP C2/C7) without re-deriving parameters every release.
- You want **FIPS 140-2/3 readiness** by toggling a feature flag (`aws-lc-rs` backend).
- You want **mobile secure storage** primitives (`SensitiveBuffer`, `BackupExclusion`, MASVS-STORAGE-1).

## Install

```toml
[dependencies]
secure_data = { version = "0.1", features = ["password"] }
```

## Quick examples

### Typed secret wrappers

```rust
use secure_data::secret::SecretString;

let token = SecretString::new("super-secret-api-key".to_owned());
println!("{:?}", token);  // -> SecretString([REDACTED])
// Only call expose_secret() at the boundary that actually needs the bytes.
let bytes = token.expose_secret();
```

### Argon2id password hashing (`features = ["password"]`)

```rust
use secure_data::password::{hash_password, verify_password};
use secure_data::secret::SecretString;

let password = SecretString::new("correct-horse-battery".to_owned());
let hash = hash_password(&password)?;
assert!(verify_password(&password, &hash)?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Envelope encryption with a key provider

```rust
use secure_data::envelope::{encrypt_for_storage, decrypt_for_use};
use secure_data::kms::StaticDevKeyProvider;
use std::sync::Arc;

let kms = Arc::new(StaticDevKeyProvider::with_dev_key());
let plaintext = b"private medical record";

let envelope = encrypt_for_storage(&*kms, "phi:patient:42", plaintext)?;
// envelope.ciphertext is AES-256-GCM, envelope.wrapped_dek is the KMS-wrapped DEK.

let recovered = decrypt_for_use(&*kms, &envelope)?;
assert_eq!(recovered.as_slice(), plaintext);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What's inside

| Module | Use it for |
|---|---|
| `secret` | `SecretString`, `SecretBytes`, `ApiToken`, `DbPassword`, `SigningKeyRef` — types that won't leak via Debug/Display/Serialize and zero on drop. |
| `envelope` | `encrypt_for_storage`, `decrypt_for_use` — AES-256-GCM envelope encryption. |
| `kms` | `KeyProvider` trait + `StaticDevKeyProvider` for tests. |
| `providers` | Real KMS providers (Vault, AWS KMS) gated by features. |
| `keyring` | Logical key registry with aliases, versions, and lifecycle (`Active`, `RotatingFrom`, `Deprecated`). |
| `rotation` | Re-encryption helpers for key rotation with dual-read. |
| `algorithm` | `CryptoAlgorithm`, `AlgorithmPolicy` — algorithm selection and downgrade prevention. |
| `password` | Argon2id `hash_password` / `verify_password` (feature `password`). |
| `config` / `resolve` | `vault://`, `kms://`, `env://` reference parsing and resolution. |
| `memory` | `Zeroize` and `ReadOnce` helpers. |
| `serde` | Safe serializers for secret-bearing structs. |
| `mobile_storage` | `SensitiveBuffer`, `BackupExclusion`, `MobileStoragePolicy` (feature `mobile-storage`, MASVS-STORAGE-1). |

## Feature flags

| Flag | Dependency | Purpose |
|---|---|---|
| `vault` | `reqwest` | HashiCorp Vault Transit key provider + KV secret resolution. |
| `aws-kms` | `aws-sdk-kms`, `aws-config` | AWS KMS `GenerateDataKey` / `Decrypt` provider. |
| `azure-kv` | — | Azure Key Vault key provider (wrap/unwrap only). |
| `fips` | `aws-lc-rs` | FIPS 140-2/3 validated AEAD backend. |
| `password` | `argon2` | Argon2id password hashing. |
| `mobile-storage` | — | Mobile secure-storage primitives (MASVS-STORAGE). |

All features are off by default. Combine freely: `cargo add secure_data --features vault,aws-kms,password`.

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- Zeroize-on-drop wherever a secret is held

## Status

Alpha.

## Related crates

Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace:

| Crate | Purpose |
|---|---|
| [`security_core`](https://crates.io/crates/security_core) | Shared types, identity, classification, severity, redaction. |
| [`security_events`](https://crates.io/crates/security_events) | Security logging and tamper-evident audit chain. |
| [`secure_errors`](https://crates.io/crates/secure_errors) | Three-layer error model with redaction-safe public errors. |
| [`secure_output`](https://crates.io/crates/secure_output) | Context-aware output encoders (HTML, JSON, URL, JS, CSS, XML, LDAP, shell). |
| [`secure_network`](https://crates.io/crates/secure_network) | TLS policy, SPKI pinning, mTLS, cleartext detection. |
| [`secure_device_trust`](https://crates.io/crates/secure_device_trust) | Native-client device trust and session certificates. |
| [`secure_resilience`](https://crates.io/crates/secure_resilience) | RASP and environment-detection policy. |
| [`secure_privacy`](https://crates.io/crates/secure_privacy) | PII classification, consent, retention, pseudonymization. |
| [`secure_boundary`](https://crates.io/crates/secure_boundary) | Input validation, security headers, boundary protections. |
| [`secure_identity`](https://crates.io/crates/secure_identity) | JWT/OIDC, MFA, sessions, biometric step-up. |
| [`secure_authz`](https://crates.io/crates/secure_authz) | Typed deny-by-default authorization with device-trust predicates. |

## Getting help

- **Questions, ideas, design discussions** — open a [GitHub Discussion](https://github.com/kerberosmansour/SunLitSecurityLibraries/discussions).
- **Bug reports** — use the bug-report template in [GitHub Issues](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues).
- **Security issues** — please do **not** open a public issue. See [SECURITY.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/SECURITY.md) for the responsible-disclosure process.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CONTRIBUTING.md) and the [Code of Conduct](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/CODE_OF_CONDUCT.md) before opening a PR.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

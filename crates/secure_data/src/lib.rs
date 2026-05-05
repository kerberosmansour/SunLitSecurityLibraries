#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_data` — Data protection, secrets management & FIPS readiness (OWASP C8).
//!
//! This crate provides:
//! - Typed secret wrappers that suppress `Debug`, `Display`, and default `Serialize` output.
//! - Pluggable key-provider abstraction with a `StaticDevKeyProvider` for tests.
//! - Envelope encryption/decryption via AES-256-GCM (FIPS-ready `aws-lc-rs` behind `fips` feature).
//! - Key ring lifecycle management with rotation and dual-read support.
//! - Secret reference parsing (`vault://`, `kms://`, `env://`).
//! - Zeroization and `ReadOnce` memory helpers.

/// Crypto algorithm selection and policy — `CryptoAlgorithm`, `AlgorithmPolicy`.
pub mod algorithm;
/// Secret reference parsing — `vault://`, `kms://`, `env://`.
pub mod config;
/// Envelope encryption and decryption — `encrypt_for_storage`, `decrypt_for_use`.
pub mod envelope;
/// Error types for `secure_data` operations.
pub mod error;
/// Azure Key Vault key provider — wrap/unwrap only (behind `azure-kv` feature).
#[cfg(feature = "azure-kv")]
pub mod key_vault;
/// Key ring — logical key registry with aliases, versions, and lifecycle management.
pub mod keyring;
/// Key provider abstraction and `StaticDevKeyProvider`.
pub mod kms;
/// Zeroization and `ReadOnce` memory safety helpers.
pub mod memory;
/// Password hashing and verification — Argon2id default (OWASP C2/C7).
#[cfg(feature = "password")]
pub mod password;
/// Post-quantum primitives — size constants and combiner identifiers (M1).
/// The hybrid X25519 + ML-KEM-768 KEM implementation lands behind the `pq`
/// feature flag in M2; M1 reserves the public surface so downstream
/// consumers can pin against an envelope shape that will not break when
/// M2 ships. See `docs/slo/design/pq-migration-plan.md`.
pub mod pq;
/// Real key provider implementations (Vault, AWS KMS) behind feature flags.
pub mod providers;
/// Secret reference resolution — `resolve_secret()`.
pub mod resolve;
/// Key rotation and re-encryption helpers.
pub mod rotation;
/// Typed secret wrappers: `SecretString`, `SecretBytes`, `ApiToken`, `DbPassword`, `SigningKeyRef`.
pub mod secret;
/// Safe serialization helpers for secret-bearing structs.
pub mod serde;

/// Mobile storage extensions — `SensitiveBuffer` and `MobileStoragePolicy` (MASVS-STORAGE).
#[cfg(feature = "mobile-storage")]
pub mod mobile_storage;

/// Kani proof harnesses (compiled only under `cargo kani`).
///
/// Excluded from regular builds via `#![cfg(kani)]` at the module root —
/// adding harnesses has zero impact on the production crate. See
/// `docs/dev-guide/formal-verification.md` for the proof catalogue and
/// `.github/workflows/kani.yml` for the advisory CI lane.
#[cfg(kani)]
mod proofs;

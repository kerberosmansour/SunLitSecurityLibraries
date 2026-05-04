//! Real key provider implementations behind feature flags.
//!
//! - `vault` feature: `VaultKeyProvider` — HashiCorp Vault Transit secrets engine.
//! - `aws-kms` feature: `AwsKmsKeyProvider` — AWS KMS `GenerateDataKey`/`Decrypt`.

#[cfg(feature = "vault")]
pub mod vault;

#[cfg(feature = "aws-kms")]
pub mod aws_kms;

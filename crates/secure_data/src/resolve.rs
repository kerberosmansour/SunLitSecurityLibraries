//! Secret reference resolution — `resolve_secret()`.
//!
//! Resolves a `SecretReference` to its actual string value at runtime.
//!
//! | Scheme | Resolution | Feature required |
//! |--------|-----------|-----------------|
//! | `env://VAR` | `std::env::var(VAR)` | none |
//! | `vault://path#field` | Vault KV v1 GET | `vault` |
//! | `kms://...` | Not supported (KMS keys are not string secrets) | — |

use crate::config::{SecretReference, SecretReferenceProvider};
use crate::error::DataError;
use crate::secret::SecretString;

/// Resolves a [`SecretReference`] to a [`SecretString`] value.
///
/// - `env://VAR` — reads the environment variable `VAR` at call time.
///   Returns [`DataError::SecretNotFound`] if the variable is not set.
/// - `vault://path#field` — reads a KV v1 secret from HashiCorp Vault.
///   Requires `VAULT_ADDR` and `VAULT_TOKEN` environment variables.
///   Only available when the `vault` feature is enabled.
/// - `kms://...` — returns [`DataError::InvalidSecretReference`] because
///   KMS key aliases are not directly resolvable to string secrets.
///
/// # Errors
/// Returns [`DataError`] on resolution failure.
pub async fn resolve_secret(reference: &SecretReference) -> Result<SecretString, DataError> {
    match reference.provider {
        SecretReferenceProvider::Env => resolve_env(reference),
        SecretReferenceProvider::Vault => resolve_vault(reference).await,
        SecretReferenceProvider::Kms => Err(DataError::InvalidSecretReference {
            input: format!("kms://{}", reference.path),
        }),
    }
}

// --- env:// resolution -------------------------------------------------------

fn resolve_env(reference: &SecretReference) -> Result<SecretString, DataError> {
    std::env::var(&reference.path)
        .map(SecretString::new)
        .map_err(|_| DataError::SecretNotFound {
            reference: format!("env://{}", reference.path),
        })
}

// --- vault:// resolution -----------------------------------------------------

#[cfg(feature = "vault")]
async fn resolve_vault(reference: &SecretReference) -> Result<SecretString, DataError> {
    let vault_addr = std::env::var("VAULT_ADDR").map_err(|_| DataError::ProviderUnavailable {
        provider: "vault".to_string(),
        reason: "VAULT_ADDR environment variable not set".to_string(),
    })?;
    let vault_token = std::env::var("VAULT_TOKEN").map_err(|_| DataError::ProviderUnavailable {
        provider: "vault".to_string(),
        reason: "VAULT_TOKEN environment variable not set".to_string(),
    })?;

    let value = crate::providers::vault::fetch_vault_kv_secret(
        &vault_addr,
        &vault_token,
        &reference.path,
        reference.field.as_deref(),
    )
    .await?;

    Ok(SecretString::new(value))
}

#[cfg(not(feature = "vault"))]
async fn resolve_vault(_reference: &SecretReference) -> Result<SecretString, DataError> {
    Err(DataError::ProviderUnavailable {
        provider: "vault".to_string(),
        reason: "vault feature not enabled — recompile with --features vault".to_string(),
    })
}

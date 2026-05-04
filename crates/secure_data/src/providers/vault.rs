//! HashiCorp Vault Transit secrets engine key provider.
//!
//! Uses the Vault Transit API to generate and unwrap data-encryption keys.
//! Auth is via a Vault token (`X-Vault-Token` header).
//!
//! The wrapped DEK stored in [`WrappedDataKey`] is the UTF-8 bytes of the
//! Vault ciphertext string (e.g. `vault:v1:...`).
//!
//! **Feature flag**: only compiled when the `vault` feature is enabled.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::DataError;
use crate::kms::{DataKey, KeyAlias, WrappedDataKey};

/// HashiCorp Vault Transit key provider.
///
/// Calls the Vault Transit API to generate and unwrap data-encryption keys.
/// Credentials are supplied at construction time — never hard-coded.
pub struct VaultKeyProvider {
    client: reqwest::Client,
    vault_addr: String,
    vault_token: String,
}

impl VaultKeyProvider {
    /// Creates a new `VaultKeyProvider`.
    ///
    /// # Arguments
    /// - `vault_addr`: base URL of the Vault server (e.g. `https://vault.example.com:8200`)
    /// - `vault_token`: Vault token with Transit access
    ///
    /// # Errors
    /// Returns [`DataError::ProviderUnavailable`] if the HTTP client cannot be built.
    pub fn new(
        vault_addr: impl Into<String>,
        vault_token: impl Into<String>,
    ) -> Result<Self, DataError> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| DataError::ProviderUnavailable {
                provider: "vault".to_string(),
                reason: format!("failed to build HTTP client: {e}"),
            })?;
        Ok(Self {
            client,
            vault_addr: vault_addr.into(),
            vault_token: vault_token.into(),
        })
    }
}

// --- Vault API response types ------------------------------------------------

#[derive(Deserialize)]
struct VaultDataKeyResponse {
    data: VaultDataKeyData,
}

#[derive(Deserialize)]
struct VaultDataKeyData {
    plaintext: String,
    ciphertext: String,
    key_version: u64,
}

#[derive(Deserialize)]
struct VaultDecryptResponse {
    data: VaultDecryptData,
}

#[derive(Deserialize)]
struct VaultDecryptData {
    plaintext: String,
}

// --- Sealed impl + KeyProvider impl -----------------------------------------

impl crate::kms::private::Sealed for VaultKeyProvider {}

impl crate::kms::KeyProvider for VaultKeyProvider {
    fn generate_data_key(
        &self,
        alias: &KeyAlias,
    ) -> impl std::future::Future<Output = Result<(DataKey, WrappedDataKey, String), DataError>> + Send
    {
        let url = format!("{}/v1/transit/datakey/plaintext/{}", self.vault_addr, alias);
        let token = self.vault_token.clone();
        let client = self.client.clone();

        async move {
            let resp = client
                .post(&url)
                .header("X-Vault-Token", &token)
                .header("Content-Type", "application/json")
                .body("{}")
                .send()
                .await
                .map_err(|e| DataError::ProviderUnavailable {
                    provider: "vault".to_string(),
                    reason: e.to_string(),
                })?;

            let status = resp.status();
            if status == reqwest::StatusCode::FORBIDDEN
                || status == reqwest::StatusCode::UNAUTHORIZED
            {
                return Err(DataError::ProviderAuthError {
                    provider: "vault".to_string(),
                    reason: format!("HTTP {status}"),
                });
            }
            if !status.is_success() {
                return Err(DataError::ProviderUnavailable {
                    provider: "vault".to_string(),
                    reason: format!("HTTP {status}"),
                });
            }

            let parsed: VaultDataKeyResponse =
                resp.json()
                    .await
                    .map_err(|e| DataError::ProviderUnavailable {
                        provider: "vault".to_string(),
                        reason: format!("failed to parse response: {e}"),
                    })?;

            let dek_bytes =
                B64.decode(&parsed.data.plaintext)
                    .map_err(|e| DataError::ProviderUnavailable {
                        provider: "vault".to_string(),
                        reason: format!("base64 decode error: {e}"),
                    })?;

            let dek = Zeroizing::new(dek_bytes);
            let wrapped = parsed.data.ciphertext.into_bytes();
            let version = format!("v{}", parsed.data.key_version);

            Ok((dek, wrapped, version))
        }
    }

    fn unwrap_data_key(
        &self,
        wrapped: &WrappedDataKey,
        alias: &KeyAlias,
        _version: &str,
    ) -> impl std::future::Future<Output = Result<DataKey, DataError>> + Send {
        let url = format!("{}/v1/transit/decrypt/{}", self.vault_addr, alias);
        let token = self.vault_token.clone();
        let client = self.client.clone();

        // The wrapped key is stored as UTF-8 bytes of the vault ciphertext string
        let ciphertext = String::from_utf8_lossy(wrapped).into_owned();

        async move {
            let body = serde_json::json!({ "ciphertext": ciphertext });

            let resp = client
                .post(&url)
                .header("X-Vault-Token", &token)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| DataError::ProviderUnavailable {
                    provider: "vault".to_string(),
                    reason: e.to_string(),
                })?;

            let status = resp.status();
            if status == reqwest::StatusCode::FORBIDDEN
                || status == reqwest::StatusCode::UNAUTHORIZED
            {
                return Err(DataError::ProviderAuthError {
                    provider: "vault".to_string(),
                    reason: format!("HTTP {status}"),
                });
            }
            if !status.is_success() {
                return Err(DataError::ProviderUnavailable {
                    provider: "vault".to_string(),
                    reason: format!("HTTP {status}"),
                });
            }

            let parsed: VaultDecryptResponse =
                resp.json()
                    .await
                    .map_err(|e| DataError::ProviderUnavailable {
                        provider: "vault".to_string(),
                        reason: format!("failed to parse response: {e}"),
                    })?;

            let dek_bytes =
                B64.decode(&parsed.data.plaintext)
                    .map_err(|e| DataError::ProviderUnavailable {
                        provider: "vault".to_string(),
                        reason: format!("base64 decode error: {e}"),
                    })?;

            Ok(Zeroizing::new(dek_bytes))
        }
    }
}

// --- Vault KV resolve support ------------------------------------------------

/// Fetches a KV v1 secret from Vault.
///
/// Used by `resolve_secret()` for `vault://` references.
pub(crate) async fn fetch_vault_kv_secret(
    vault_addr: &str,
    vault_token: &str,
    path: &str,
    field: Option<&str>,
) -> Result<String, DataError> {
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .map_err(|e| DataError::ProviderUnavailable {
            provider: "vault".to_string(),
            reason: format!("failed to build HTTP client: {e}"),
        })?;

    let url = format!("{vault_addr}/v1/{path}");
    let resp = client
        .get(&url)
        .header("X-Vault-Token", vault_token)
        .send()
        .await
        .map_err(|e| DataError::ProviderUnavailable {
            provider: "vault".to_string(),
            reason: e.to_string(),
        })?;

    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(DataError::ProviderAuthError {
            provider: "vault".to_string(),
            reason: format!("HTTP {status}"),
        });
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(DataError::SecretNotFound {
            reference: format!("vault://{path}"),
        });
    }
    if !status.is_success() {
        return Err(DataError::ProviderUnavailable {
            provider: "vault".to_string(),
            reason: format!("HTTP {status}"),
        });
    }

    let json: serde_json::Value =
        resp.json()
            .await
            .map_err(|e| DataError::ProviderUnavailable {
                provider: "vault".to_string(),
                reason: format!("failed to parse KV response: {e}"),
            })?;

    let data = json
        .get("data")
        .ok_or_else(|| DataError::ProviderUnavailable {
            provider: "vault".to_string(),
            reason: "missing 'data' field in KV response".to_string(),
        })?;

    let field_name = field.unwrap_or("value");
    let value = data
        .get(field_name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| DataError::SecretNotFound {
            reference: format!("vault://{path}#{field_name}"),
        })?;

    Ok(value.to_string())
}

// Azure Key Vault key provider — wrap/unwrap only.
//
// This module provides an Azure Key Vault-backed `KeyProvider` implementation.
// Key material never leaves the vault in production — only wrap/unwrap operations
// are performed. A `MockVaultClient` is included for deterministic testing.

use std::future::Future;
use zeroize::Zeroizing;

use crate::error::DataError;
use crate::kms::{self, DataKey, KeyAlias, WrappedDataKey};

/// Abstraction over Azure Key Vault HTTP API.
///
/// In production, implement this trait against the Azure SDK. For tests,
/// use [`MockVaultClient`].
///
/// # Examples
///
/// ```
/// use secure_data::key_vault::MockVaultClient;
///
/// let client = MockVaultClient::new();
/// // Use with AzureKeyVaultProvider for testing
/// ```
pub trait VaultClient: Send + Sync {
    /// Wraps (encrypts) a data key using the vault's KEK.
    fn wrap_key(
        &self,
        key_name: &str,
        plaintext_key: &[u8],
    ) -> impl Future<Output = Result<(Vec<u8>, String), DataError>> + Send;

    /// Unwraps (decrypts) a previously wrapped data key.
    fn unwrap_key(
        &self,
        key_name: &str,
        wrapped_key: &[u8],
        version: &str,
    ) -> impl Future<Output = Result<Vec<u8>, DataError>> + Send;
}

/// A mock vault client for testing.
///
/// Wraps keys with a simple XOR scheme (not secure — test only).
/// Use [`MockVaultClient::failing`] to simulate vault unavailability.
///
/// # Examples
///
/// ```
/// use secure_data::key_vault::{MockVaultClient, AzureKeyVaultProvider};
///
/// let mock = MockVaultClient::new();
/// let provider = AzureKeyVaultProvider::new(mock);
/// ```
pub struct MockVaultClient {
    should_fail: bool,
}

impl MockVaultClient {
    /// Creates a mock vault client that succeeds.
    #[must_use]
    pub fn new() -> Self {
        Self { should_fail: false }
    }

    /// Creates a mock vault client that always fails with `ProviderUnavailable`.
    #[must_use]
    pub fn failing() -> Self {
        Self { should_fail: true }
    }
}

impl Default for MockVaultClient {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultClient for MockVaultClient {
    fn wrap_key(
        &self,
        _key_name: &str,
        plaintext_key: &[u8],
    ) -> impl Future<Output = Result<(Vec<u8>, String), DataError>> + Send {
        let should_fail = self.should_fail;
        let key_copy = plaintext_key.to_vec();
        async move {
            if should_fail {
                return Err(DataError::ProviderUnavailable {
                    provider: "azure-kv".to_string(),
                    reason: "vault unavailable (mock)".to_string(),
                });
            }
            // Simple XOR wrap for testing (deterministic, reversible)
            let mock_kek = [0xABu8; 32];
            let wrapped: Vec<u8> = key_copy
                .iter()
                .zip(mock_kek.iter().cycle())
                .map(|(p, k)| p ^ k)
                .collect();
            Ok((wrapped, "mock-v1".to_string()))
        }
    }

    fn unwrap_key(
        &self,
        _key_name: &str,
        wrapped_key: &[u8],
        _version: &str,
    ) -> impl Future<Output = Result<Vec<u8>, DataError>> + Send {
        let should_fail = self.should_fail;
        let wrapped_copy = wrapped_key.to_vec();
        async move {
            if should_fail {
                return Err(DataError::ProviderUnavailable {
                    provider: "azure-kv".to_string(),
                    reason: "vault unavailable (mock)".to_string(),
                });
            }
            // Reverse the XOR wrap
            let mock_kek = [0xABu8; 32];
            let unwrapped: Vec<u8> = wrapped_copy
                .iter()
                .zip(mock_kek.iter().cycle())
                .map(|(w, k)| w ^ k)
                .collect();
            Ok(unwrapped)
        }
    }
}

/// Azure Key Vault-backed key provider.
///
/// Delegates key wrap/unwrap operations to an Azure Key Vault instance
/// (or a [`MockVaultClient`] for testing). Key material never leaves the
/// vault in production use.
///
/// # Examples
///
/// ```
/// use secure_data::key_vault::{AzureKeyVaultProvider, MockVaultClient};
///
/// let provider = AzureKeyVaultProvider::new(MockVaultClient::new());
/// ```
pub struct AzureKeyVaultProvider<C: VaultClient> {
    client: C,
}

impl<C: VaultClient> AzureKeyVaultProvider<C> {
    /// Creates a new Azure Key Vault provider with the given vault client.
    #[must_use]
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C: VaultClient> kms::private::Sealed for AzureKeyVaultProvider<C> {}

impl<C: VaultClient> kms::KeyProvider for AzureKeyVaultProvider<C> {
    fn generate_data_key(
        &self,
        alias: &KeyAlias,
    ) -> impl Future<Output = Result<(DataKey, WrappedDataKey, String), DataError>> + Send {
        let alias = alias.to_string();
        async move {
            // Generate a random 32-byte DEK locally
            use rand::RngCore;
            let mut dek = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut dek);

            // Wrap via vault — key material is sent to vault only for wrapping
            let (wrapped, version) = self.client.wrap_key(&alias, &dek).await?;

            Ok((Zeroizing::new(dek), wrapped, version))
        }
    }

    fn unwrap_data_key(
        &self,
        wrapped: &WrappedDataKey,
        alias: &KeyAlias,
        version: &str,
    ) -> impl Future<Output = Result<DataKey, DataError>> + Send {
        let alias = alias.to_string();
        let wrapped = wrapped.clone();
        let version = version.to_string();
        async move {
            let dek = self.client.unwrap_key(&alias, &wrapped, &version).await?;
            Ok(Zeroizing::new(dek))
        }
    }
}

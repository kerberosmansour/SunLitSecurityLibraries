//! BDD tests for Azure Key Vault provider (mock-based) — Milestone 25
//!
//! Feature: Azure Key Vault provider
//! These tests use a mock Key Vault, not real Azure infrastructure.

// Azure Key Vault tests are gated behind the `azure-kv` feature.
// Run with: cargo test -p secure_data --features azure-kv --test sunlit_owasp_keyvault

#[cfg(feature = "azure-kv")]
mod azure_kv_tests {
    use secure_data::key_vault::{AzureKeyVaultProvider, MockVaultClient};
    use secure_data::kms::KeyProvider;

    /// Scenario: Wrap key via vault
    /// Given: Mock Key Vault provider
    /// When: wrap_key()
    /// Then: Returns wrapped key blob
    #[tokio::test]
    async fn test_wrap_key_via_vault() {
        // Given: mock vault
        let mock = MockVaultClient::new();
        let provider = AzureKeyVaultProvider::new(mock);

        // When: generate data key (wrap)
        let result = provider.generate_data_key("vault-key").await;

        // Then: succeeds with wrapped key
        assert!(result.is_ok(), "wrap_key must succeed with mock vault");
        let (_dek, wrapped, version) = result.unwrap();
        assert!(!wrapped.is_empty(), "wrapped key must not be empty");
        assert!(!version.is_empty(), "version must not be empty");
    }

    /// Scenario: Unwrap key via vault
    /// Given: Mock Key Vault provider and wrapped blob
    /// When: unwrap_key()
    /// Then: Returns usable DEK
    #[tokio::test]
    async fn test_unwrap_key_via_vault() {
        // Given: generate key pair via mock
        let mock = MockVaultClient::new();
        let provider = AzureKeyVaultProvider::new(mock);
        let (original_dek, wrapped, version) = provider
            .generate_data_key("vault-key")
            .await
            .expect("wrap must succeed");

        // When: unwrap
        let unwrapped = provider
            .unwrap_data_key(&wrapped, "vault-key", &version)
            .await
            .expect("unwrap must succeed");

        // Then: matches original
        assert_eq!(
            *unwrapped, *original_dek,
            "unwrapped key must match original"
        );
    }

    /// Scenario: Vault unavailable
    /// Given: Mock vault returns error
    /// When: wrap_key()
    /// Then: Returns error vault_unavailable; no panic
    #[tokio::test]
    async fn test_vault_unavailable() {
        // Given: failing mock
        let mock = MockVaultClient::failing();
        let provider = AzureKeyVaultProvider::new(mock);

        // When: attempt key generation
        let result = provider.generate_data_key("vault-key").await;

        // Then: returns error, no panic
        assert!(result.is_err(), "must return error when vault unavailable");
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unavailable") || msg.contains("vault") || msg.contains("provider"),
            "error must mention vault unavailability, got: {msg}"
        );
    }
}

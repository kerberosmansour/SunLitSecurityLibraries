//! AWS KMS key provider.
//!
//! Uses `aws-sdk-kms` to call `GenerateDataKey` and `Decrypt`.
//! AWS credentials are loaded from the standard credential chain
//! (env vars, shared credentials file, IAM role, etc.).
//!
//! **Feature flag**: only compiled when the `aws-kms` feature is enabled.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use zeroize::Zeroizing;

use crate::error::DataError;
use crate::kms::{DataKey, KeyAlias, WrappedDataKey};

/// AWS KMS key provider.
///
/// Wraps `aws-sdk-kms::Client` to implement [`crate::kms::KeyProvider`] for AWS KMS.
/// AWS credentials are resolved from the standard chain at construction time.
pub struct AwsKmsKeyProvider {
    client: aws_sdk_kms::Client,
}

impl AwsKmsKeyProvider {
    /// Creates an `AwsKmsKeyProvider` using the standard AWS credential chain.
    pub async fn new() -> Self {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = aws_sdk_kms::Client::new(&config);
        Self { client }
    }

    /// Creates an `AwsKmsKeyProvider` pointing at a custom endpoint URL.
    ///
    /// Used in tests to point at a local mock KMS server.
    pub async fn with_endpoint(endpoint_url: impl Into<String>) -> Self {
        let endpoint = endpoint_url.into();
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .endpoint_url(&endpoint)
            .region(aws_config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_kms::config::Credentials::new(
                "test-key-id",
                "test-secret-key",
                None,
                None,
                "test",
            ))
            .load()
            .await;
        let client = aws_sdk_kms::Client::new(&config);
        Self { client }
    }

    /// Creates an `AwsKmsKeyProvider` from an already-built `aws-sdk-kms` client.
    ///
    /// Allows injecting a pre-configured client (e.g. for testing with LocalStack).
    #[must_use]
    pub fn with_client(client: aws_sdk_kms::Client) -> Self {
        Self { client }
    }
}

// --- Sealed impl + KeyProvider impl -----------------------------------------

impl crate::kms::private::Sealed for AwsKmsKeyProvider {}

impl crate::kms::KeyProvider for AwsKmsKeyProvider {
    fn generate_data_key(
        &self,
        alias: &KeyAlias,
    ) -> impl std::future::Future<Output = Result<(DataKey, WrappedDataKey, String), DataError>> + Send
    {
        let client = self.client.clone();
        let key_id = alias.to_string();

        async move {
            let resp = client
                .generate_data_key()
                .key_id(&key_id)
                .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
                .send()
                .await
                .map_err(|e| map_kms_error(e.into()))?;

            let plaintext_blob =
                resp.plaintext()
                    .ok_or_else(|| DataError::ProviderUnavailable {
                        provider: "aws-kms".to_string(),
                        reason: "GenerateDataKey response missing Plaintext".to_string(),
                    })?;

            let ciphertext_blob =
                resp.ciphertext_blob()
                    .ok_or_else(|| DataError::ProviderUnavailable {
                        provider: "aws-kms".to_string(),
                        reason: "GenerateDataKey response missing CiphertextBlob".to_string(),
                    })?;

            let dek = Zeroizing::new(plaintext_blob.as_ref().to_vec());
            let wrapped = ciphertext_blob.as_ref().to_vec();
            let version = "1".to_string();

            Ok((dek, wrapped, version))
        }
    }

    fn unwrap_data_key(
        &self,
        wrapped: &WrappedDataKey,
        _alias: &KeyAlias,
        _version: &str,
    ) -> impl std::future::Future<Output = Result<DataKey, DataError>> + Send {
        let client = self.client.clone();
        let ciphertext_blob = aws_sdk_kms::primitives::Blob::new(wrapped.clone());

        async move {
            let resp = client
                .decrypt()
                .ciphertext_blob(ciphertext_blob)
                .send()
                .await
                .map_err(|e| map_kms_error(e.into()))?;

            let plaintext_blob =
                resp.plaintext()
                    .ok_or_else(|| DataError::ProviderUnavailable {
                        provider: "aws-kms".to_string(),
                        reason: "Decrypt response missing Plaintext".to_string(),
                    })?;

            Ok(Zeroizing::new(plaintext_blob.as_ref().to_vec()))
        }
    }
}

// --- Error mapping ----------------------------------------------------------

fn map_kms_error(e: Box<dyn std::error::Error + Send + Sync>) -> DataError {
    let msg = e.to_string();
    // Check for auth errors
    if msg.contains("AccessDeniedException")
        || msg.contains("InvalidSignatureException")
        || msg.contains("AuthFailure")
        || msg.contains("UnauthorizedOperation")
    {
        return DataError::ProviderAuthError {
            provider: "aws-kms".to_string(),
            reason: msg,
        };
    }
    // All other errors (connection refused, timeout, etc.) → unavailable
    DataError::ProviderUnavailable {
        provider: "aws-kms".to_string(),
        reason: msg,
    }
}

// --- JSON mock support for tests (parses AWS-format JSON responses) ----------
// The aws-sdk-kms uses its own HTTP layer. When endpoint_url is overridden
// to a mock server, the SDK sends real AWS-protocol requests and parses
// the mock's JSON responses. No special handling needed here — the SDK
// handles response parsing.

/// Decodes a base64-encoded value from an AWS KMS JSON response field.
///
/// Used internally for parsing custom mock responses in tests.
#[allow(dead_code)]
fn decode_b64(value: &str) -> Result<Vec<u8>, DataError> {
    B64.decode(value)
        .map_err(|e| DataError::ProviderUnavailable {
            provider: "aws-kms".to_string(),
            reason: format!("base64 decode error: {e}"),
        })
}

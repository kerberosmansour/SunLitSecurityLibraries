//! BDD tests for AwsKmsKeyProvider — Milestone 13
//!
//! Feature: AwsKmsKeyProvider
//!
//! These tests require the `aws-kms` feature flag.
#![cfg(feature = "aws-kms")]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use secure_data::kms::KeyProvider;
use secure_data::providers::aws_kms::AwsKmsKeyProvider;
use std::io::{Read, Write};
use std::net::TcpListener;

// Fixed 32-byte test DEK (all-0x99 bytes for determinism)
const TEST_DEK_BYTES: [u8; 32] = [0x99u8; 32];
const TEST_WRAPPED_BYTES: [u8; 32] = [0xABu8; 32];

fn test_dek_b64() -> String {
    B64.encode(TEST_DEK_BYTES)
}

fn test_wrapped_b64() -> String {
    B64.encode(TEST_WRAPPED_BYTES)
}

fn make_generate_response() -> String {
    let dek_b64 = test_dek_b64();
    let wrapped_b64 = test_wrapped_b64();
    let body = format!(
        r#"{{"Plaintext":"{dek_b64}","CiphertextBlob":"{wrapped_b64}","KeyId":"arn:aws:kms:us-east-1:123456789012:key/test-key-id"}}"#
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn make_decrypt_response() -> String {
    let dek_b64 = test_dek_b64();
    let body = format!(
        r#"{{"Plaintext":"{dek_b64}","KeyId":"arn:aws:kms:us-east-1:123456789012:key/test-key-id"}}"#
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Start a synchronous mock HTTP server in a background thread.
fn start_mock_server(responses: Vec<String>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for response in responses {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(_) => break,
            }
        }
    });
    port
}

/// Scenario: Generate data key — happy path
/// Given AWS KMS key alias exists (mock)
/// When generate_data_key(alias)
/// Then returns (DEK, WrappedDEK, version)
#[tokio::test]
async fn test_aws_kms_generate_data_key_happy_path() {
    // Given: mock KMS endpoint
    let port = start_mock_server(vec![make_generate_response()]);
    let provider = AwsKmsKeyProvider::with_endpoint(format!("http://127.0.0.1:{port}")).await;

    // When: generate_data_key is called
    let result = provider.generate_data_key("alias/my-key").await;

    // Then: returns (DEK, WrappedDEK, version)
    let (dek, wrapped, version) = result.expect("generate_data_key must succeed");
    assert_eq!(
        dek.as_slice(),
        &TEST_DEK_BYTES,
        "DEK must match mock response"
    );
    assert!(!wrapped.is_empty(), "wrapped key must not be empty");
    assert!(!version.is_empty(), "version must not be empty");
}

/// Scenario: Unwrap data key — happy path
/// Given a previously wrapped key
/// When unwrap_data_key(wrapped, alias, version)
/// Then returns original DEK
#[tokio::test]
async fn test_aws_kms_unwrap_data_key_happy_path() {
    // Given: mock KMS endpoint
    let port = start_mock_server(vec![make_decrypt_response()]);
    let provider = AwsKmsKeyProvider::with_endpoint(format!("http://127.0.0.1:{port}")).await;
    let wrapped = TEST_WRAPPED_BYTES.to_vec();

    // When: unwrap_data_key is called
    let result = provider
        .unwrap_data_key(&wrapped, "alias/my-key", "1")
        .await;

    // Then: returns original DEK
    let dek = result.expect("unwrap_data_key must succeed");
    assert_eq!(dek.as_slice(), &TEST_DEK_BYTES, "unwrapped DEK must match");
}

/// Scenario: KMS unavailable — partial failure
/// Given AWS endpoint unreachable
/// When any operation is called
/// Then returns DataError::ProviderUnavailable
#[tokio::test]
async fn test_aws_kms_provider_unavailable() {
    use secure_data::error::DataError;

    // Given: no listener on port
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let provider = AwsKmsKeyProvider::with_endpoint(format!("http://127.0.0.1:{port}")).await;

    // When: generate_data_key is called with unreachable endpoint
    let result = provider.generate_data_key("alias/my-key").await;

    // Then: returns DataError::ProviderUnavailable
    assert!(
        matches!(result, Err(DataError::ProviderUnavailable { .. })),
        "expected ProviderUnavailable, got: {result:?}"
    );
}

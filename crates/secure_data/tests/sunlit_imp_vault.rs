//! BDD tests for VaultKeyProvider — Milestone 13
//!
//! Feature: VaultKeyProvider
//!
//! These tests require the `vault` feature flag.
#![cfg(feature = "vault")]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use secure_data::kms::KeyProvider;
use secure_data::providers::vault::VaultKeyProvider;
use std::io::{Read, Write};
use std::net::TcpListener;

// Fixed 32-byte test DEK (all-0x42 bytes for determinism)
const TEST_DEK_BYTES: [u8; 32] = [0x42u8; 32];
const TEST_CIPHERTEXT: &str = "vault:v1:test-wrapped-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn test_dek_b64() -> String {
    B64.encode(TEST_DEK_BYTES)
}

fn make_generate_response() -> String {
    let dek_b64 = test_dek_b64();
    let body = format!(
        r#"{{"data":{{"plaintext":"{dek_b64}","ciphertext":"{TEST_CIPHERTEXT}","key_version":1}}}}"#
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn make_decrypt_response() -> String {
    let dek_b64 = test_dek_b64();
    let body = format!(r#"{{"data":{{"plaintext":"{dek_b64}"}}}}"#);
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn make_auth_error_response() -> String {
    let body = r#"{"errors":["permission denied"]}"#;
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Start a synchronous mock HTTP server in a background thread.
/// Returns the port it's listening on.
/// Each item in `responses` is sent in order, one per accepted connection.
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
                    // Connection: close causes client to close and reconnect
                }
                Err(_) => break,
            }
        }
    });
    port
}

/// Scenario: Generate data key — happy path
/// Given Vault Transit endpoint available (mock)
/// When generate_data_key(alias)
/// Then returns (DEK, WrappedDEK, version)
#[tokio::test]
async fn test_vault_generate_data_key_happy_path() {
    // Given: mock Vault server returning a valid generate response
    let port = start_mock_server(vec![make_generate_response()]);
    let provider = VaultKeyProvider::new(format!("http://127.0.0.1:{port}"), "test-token")
        .expect("provider creation must succeed");

    // When: generate_data_key is called
    let result = provider.generate_data_key("my-key").await;

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
async fn test_vault_unwrap_data_key_happy_path() {
    // Given: mock Vault server returning a valid decrypt response
    let port = start_mock_server(vec![make_decrypt_response()]);
    let provider = VaultKeyProvider::new(format!("http://127.0.0.1:{port}"), "test-token")
        .expect("provider creation must succeed");
    let wrapped = TEST_CIPHERTEXT.as_bytes().to_vec();

    // When: unwrap_data_key is called
    let result = provider.unwrap_data_key(&wrapped, "my-key", "v1").await;

    // Then: returns original DEK
    let dek = result.expect("unwrap_data_key must succeed");
    assert_eq!(dek.as_slice(), &TEST_DEK_BYTES, "unwrapped DEK must match");
}

/// Scenario: Vault unavailable — partial failure
/// Given Vault endpoint is down (no listener on port)
/// When generate_data_key(alias)
/// Then returns DataError::ProviderUnavailable
#[tokio::test]
async fn test_vault_generate_data_key_provider_unavailable() {
    use secure_data::error::DataError;

    // Given: no listener on port (bind then drop to get a free port)
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // nothing listening — connection refused

    let provider = VaultKeyProvider::new(format!("http://127.0.0.1:{port}"), "test-token")
        .expect("provider creation must succeed");

    // When: generate_data_key is called
    let result = provider.generate_data_key("my-key").await;

    // Then: returns DataError::ProviderUnavailable
    assert!(
        matches!(result, Err(DataError::ProviderUnavailable { .. })),
        "expected ProviderUnavailable, got: {result:?}"
    );
}

/// Scenario: Invalid auth token — invalid input
/// Given expired Vault token
/// When any operation is called
/// Then returns DataError::ProviderAuthError
#[tokio::test]
async fn test_vault_invalid_auth_token() {
    use secure_data::error::DataError;

    // Given: mock Vault server returning 403 Forbidden
    let port = start_mock_server(vec![make_auth_error_response()]);
    let provider = VaultKeyProvider::new(format!("http://127.0.0.1:{port}"), "expired-token")
        .expect("provider creation must succeed");

    // When: generate_data_key is called with expired token
    let result = provider.generate_data_key("my-key").await;

    // Then: returns DataError::ProviderAuthError
    assert!(
        matches!(result, Err(DataError::ProviderAuthError { .. })),
        "expected ProviderAuthError, got: {result:?}"
    );
}

/// Scenario: Encrypt/decrypt roundtrip via Vault — happy path
/// Given VaultKeyProvider wired to envelope API
/// When encrypt_for_storage then decrypt_for_use
/// Then plaintext recovered
#[tokio::test]
async fn test_vault_encrypt_decrypt_roundtrip() {
    use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};

    // Given: two mock responses (generate for encrypt, decrypt for unwrap)
    let port_gen = start_mock_server(vec![make_generate_response()]);
    let port_dec = start_mock_server(vec![make_decrypt_response()]);

    let provider_enc = VaultKeyProvider::new(format!("http://127.0.0.1:{port_gen}"), "test-token")
        .expect("provider for encryption must succeed");

    let provider_dec = VaultKeyProvider::new(format!("http://127.0.0.1:{port_dec}"), "test-token")
        .expect("provider for decryption must succeed");

    let plaintext = b"secret data for vault roundtrip test";

    // When: encrypt_for_storage
    let envelope = encrypt_for_storage(plaintext, "my-key", &provider_enc)
        .await
        .expect("encryption must succeed");

    // Then: decrypt_for_use recovers plaintext
    let recovered = decrypt_for_use(&envelope, &provider_dec)
        .await
        .expect("decryption must succeed");

    assert_eq!(
        recovered, plaintext,
        "recovered plaintext must match original"
    );
}

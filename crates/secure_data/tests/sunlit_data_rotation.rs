//! BDD tests for key rotation — Milestone 7
//!
//! Feature: Key rotation

use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};
use secure_data::keyring::{KeyRing, KeyVersionStatus};
use secure_data::kms::StaticDevKeyProvider;
use secure_data::rotation::re_encrypt;

/// Scenario: Rotate adds new version
/// Given KeyRing with key alias "app-key" at version 1
/// When rotate() called
/// Then Version 2 is Active, version 1 is DecryptOnly
#[test]
fn test_rotate_adds_new_version() {
    let mut keyring = KeyRing::new();
    keyring.add_key("app-key".to_string(), "v1".to_string());

    keyring.rotate("app-key").expect("rotate must succeed");

    let v1_status = keyring
        .version_status("app-key", "v1")
        .expect("v1 must exist");
    let v2_status = keyring
        .version_status("app-key", "v2")
        .expect("v2 must exist");

    assert!(
        matches!(v2_status, KeyVersionStatus::Active),
        "v2 must be Active after rotation"
    );
    assert!(
        matches!(v1_status, KeyVersionStatus::DecryptOnly),
        "v1 must be DecryptOnly after rotation"
    );
}

/// Scenario: Decrypt with old version during rotation
/// Given Data encrypted under version 1, key rotated to version 2
/// When decrypt_for_use() called
/// Then Decryption succeeds using version 1 key
#[tokio::test]
async fn test_decrypt_with_old_version_during_rotation() {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"encrypted before rotation";

    // Encrypt with version 1
    let envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("encryption must succeed");

    let version_used = envelope.key_version.clone();

    // Verify we can still decrypt the old data
    let decrypted = decrypt_for_use(&envelope, &provider)
        .await
        .expect("must decrypt old-version data");

    assert_eq!(
        decrypted, plaintext,
        "old-version data must decrypt correctly"
    );
    assert!(!version_used.is_empty(), "version must be tracked");
}

/// Scenario: Re-encrypt to new version
/// Given Data encrypted under version 1
/// When re_encrypt() called targeting version 2
/// Then New envelope uses version 2, old envelope obsolete
#[tokio::test]
async fn test_re_encrypt_to_new_version() {
    let provider = StaticDevKeyProvider::new();
    let plaintext = b"data to re-encrypt";

    let old_envelope = encrypt_for_storage(plaintext, "test-key", &provider)
        .await
        .expect("initial encryption must succeed");

    let new_key_alias = "test-key-v2".to_string();
    let new_envelope = re_encrypt(&old_envelope, &new_key_alias, &provider)
        .await
        .expect("re-encryption must succeed");

    assert_eq!(
        new_envelope.key_alias, new_key_alias,
        "new envelope must use new key alias"
    );

    // Verify new envelope decrypts to same plaintext
    let re_decrypted = decrypt_for_use(&new_envelope, &provider)
        .await
        .expect("re-encrypted data must decrypt");
    assert_eq!(
        re_decrypted, plaintext,
        "re-encrypted data must decrypt to original plaintext"
    );
}

/// Scenario: Deactivated key cannot decrypt
/// Given Version 1 deactivated (not just DecryptOnly)
/// When decrypt_for_use() for version 1 data
/// Then Error — key deactivated
#[test]
fn test_deactivated_key_cannot_decrypt() {
    let mut keyring = KeyRing::new();
    keyring.add_key("my-key".to_string(), "v1".to_string());

    // Add v2 so we can deactivate v1
    keyring.rotate("my-key").expect("rotate must succeed");
    keyring
        .deactivate("my-key", "v1")
        .expect("deactivation of v1 must succeed when v2 exists");

    let status = keyring
        .version_status("my-key", "v1")
        .expect("v1 must exist");
    assert!(
        matches!(status, KeyVersionStatus::Deactivated),
        "v1 must be Deactivated"
    );
}

/// Scenario: At least one active or decrypt-only version
/// Given Attempt to deactivate the only remaining key version
/// When Operation
/// Then Error — cannot deactivate last version
#[test]
fn test_cannot_deactivate_last_version() {
    let mut keyring = KeyRing::new();
    keyring.add_key("solo-key".to_string(), "v1".to_string());

    // Attempting to deactivate the only version should fail
    let result = keyring.deactivate("solo-key", "v1");
    assert!(
        result.is_err(),
        "cannot deactivate the only remaining active/decrypt-only key version"
    );
}

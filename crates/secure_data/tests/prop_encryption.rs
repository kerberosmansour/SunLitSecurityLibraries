//! Property tests — encryption roundtrip invariants.
//!
//! Milestone 9 — BDD: Encrypt/decrypt roundtrip, tampered ciphertext rejected.
use proptest::prelude::*;
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};
use secure_data::kms::StaticDevKeyProvider;
use tokio::runtime::Runtime;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Encrypt then decrypt recovers the original plaintext
    #[test]
    fn prop_encrypt_decrypt_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..256)) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let provider = StaticDevKeyProvider::new();
            let envelope = encrypt_for_storage(&plaintext, "default", &provider).await.unwrap();
            let recovered = decrypt_for_use(&envelope, &provider).await.unwrap();
            prop_assert_eq!(plaintext, recovered);
            Ok(())
        })?;
    }

    /// Tampered ciphertext is always rejected
    #[test]
    fn prop_tampered_ciphertext_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 1..128),
        flip_byte in 0usize..128,
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let provider = StaticDevKeyProvider::new();
            let mut envelope = encrypt_for_storage(&plaintext, "default", &provider).await.unwrap();
            if !envelope.ciphertext.is_empty() {
                let idx = flip_byte % envelope.ciphertext.len();
                envelope.ciphertext[idx] ^= 0xFF;
                let result = decrypt_for_use(&envelope, &provider).await;
                prop_assert!(result.is_err(), "tampered ciphertext should be rejected");
            }
            Ok(())
        })?;
    }
}

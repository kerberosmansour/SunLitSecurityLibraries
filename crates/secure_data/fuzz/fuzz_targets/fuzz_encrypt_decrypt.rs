#![no_main]
//! Fuzz target: encrypt/decrypt roundtrip never panics on arbitrary plaintext.
use libfuzzer_sys::fuzz_target;
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};
use secure_data::kms::StaticDevKeyProvider;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let provider = StaticDevKeyProvider::new();
        if let Ok(envelope) = encrypt_for_storage(data, "default", &provider).await {
            let recovered = decrypt_for_use(&envelope, &provider).await.unwrap();
            assert_eq!(data, recovered.as_slice());
        }
    });
});

//! Timing side-channel test — AEAD tag verification must not reveal plaintext length.
//!
//! Milestone 9 — BDD: Constant-time AEAD verification.
//!
//! Marked `#[ignore]` for CI. Run locally with:
//!   cargo test -p secure_data -- timing_ --ignored
use secure_data::envelope::{decrypt_for_use, encrypt_for_storage};
use secure_data::kms::StaticDevKeyProvider;
use std::time::Instant;

const SAMPLE_COUNT: usize = 100;

/// Welch's t-test statistic for two independent samples.
fn welchs_t(a: &[f64], b: &[f64]) -> f64 {
    let mean_a = a.iter().sum::<f64>() / a.len() as f64;
    let mean_b = b.iter().sum::<f64>() / b.len() as f64;
    let var_a = a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (a.len() - 1) as f64;
    let var_b = b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (b.len() - 1) as f64;
    let se = (var_a / a.len() as f64 + var_b / b.len() as f64).sqrt();
    if se == 0.0 {
        return 0.0;
    }
    ((mean_a - mean_b) / se).abs()
}

/// Timing test: AEAD decryption failure timing should not differ significantly
/// between tampered-at-start vs tampered-at-end ciphertexts.
///
/// AES-256-GCM verifies the authentication tag before decrypting, so tampering
/// anywhere in the ciphertext should be equally fast to reject. This test checks
/// for catastrophic timing differences that would indicate non-constant-time auth.
///
/// Marked `#[ignore]` — run on a quiet machine only.
#[test]
#[ignore = "timing test — run locally on a stable machine: cargo test -p secure_data -- timing_ --ignored"]
fn timing_aead_tag_verification_constant_time() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = StaticDevKeyProvider::new();
    let plaintext = vec![0xABu8; 64];

    // Create a valid envelope, then prepare two tampered variants
    let envelope = rt
        .block_on(encrypt_for_storage(&plaintext, "default", &provider))
        .expect("encryption must succeed");

    let mut tampered_start = envelope.clone();
    if !tampered_start.ciphertext.is_empty() {
        tampered_start.ciphertext[0] ^= 0xFF;
    }

    let mut tampered_end = envelope.clone();
    if !tampered_end.ciphertext.is_empty() {
        let last = tampered_end.ciphertext.len() - 1;
        tampered_end.ciphertext[last] ^= 0xFF;
    }

    // Warm-up
    for _ in 0..10 {
        let _ = rt.block_on(decrypt_for_use(&tampered_start, &provider));
        let _ = rt.block_on(decrypt_for_use(&tampered_end, &provider));
    }

    let mut times_start = Vec::with_capacity(SAMPLE_COUNT);
    let mut times_end = Vec::with_capacity(SAMPLE_COUNT);

    for _ in 0..SAMPLE_COUNT {
        let start = Instant::now();
        let _ = rt.block_on(decrypt_for_use(&tampered_start, &provider));
        times_start.push(start.elapsed().as_nanos() as f64);

        let start = Instant::now();
        let _ = rt.block_on(decrypt_for_use(&tampered_end, &provider));
        times_end.push(start.elapsed().as_nanos() as f64);
    }

    let t = welchs_t(&times_start, &times_end);
    assert!(
        t < 4.5,
        "Suspicious timing difference (Welch's t={t:.2}) between start-tampered vs \
         end-tampered ciphertext rejection. This may indicate non-constant-time AEAD tag verification."
    );
}

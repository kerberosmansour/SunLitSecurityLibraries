#![no_main]
//! Fuzz target: bounded OpenSSH public-key validation never panics for arbitrary
//! algorithm and payload fields.

use libfuzzer_sys::fuzz_target;
use secure_identity::{
    validate_openssh_public_key, validate_openssh_public_key_with_rsa_minimum_bits,
};

const ALGORITHMS: [&str; 8] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-dss",
    "rsa-sha2-256",
    "rsa-sha2-512",
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let Ok(payload) = std::str::from_utf8(payload) else {
        return;
    };
    let algorithm = ALGORITHMS[selector as usize % ALGORITHMS.len()];

    let _ = validate_openssh_public_key(algorithm, payload);
    let rsa_minimum = match selector % 4 {
        0 => 1_023,
        1 => 1_024,
        2 => 2_048,
        _ => 16_385,
    };
    let _ = validate_openssh_public_key_with_rsa_minimum_bits(
        algorithm,
        payload,
        rsa_minimum,
    );
});

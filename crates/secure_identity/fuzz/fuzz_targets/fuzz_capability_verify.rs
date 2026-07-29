#![no_main]
//! Fuzz target: capability verification never panics, and never accepts a
//! capability the pinned key did not sign.
//!
//! The second property is the load-bearing one. A panic is a denial-of-service;
//! an accepted forgery is a tenant-isolation breach.
use libfuzzer_sys::fuzz_target;
use secure_identity::capability::{CapabilityVerifier, Expected, InMemoryReplayStore, Operation};

const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0W/4g5D+qqOBSb/4gdSw
ZKtl6TqISCQfEBQKE6bZqy5InPGnVW9uboRujtzsf9hnoDxCAGvsoZ3LyJMETkCR
VsH1eSXJplm1LiXPl8nm77PTIKA36Ayt9pDXLXSfI29+mNNkmMZI82xless9zQ0w
Sjca68vaVXscQ/2ixSDemQrwoKKnoOQkRJxZPzkYizmtgaJnuG5HekAs6Rvxlco6
FwvgJqh4MmKYKGnHHiA5YSpN38G5T+S2C2UwNCfIKR7T+A2xoM6/Doik21ufbKIV
RT/4YrDPvMWcGxZZR6/wzNOET2ztlPlarvIyI3+TWjQTJxrAVZYRM8BuHT07flXX
OQIDAQAB
-----END PUBLIC KEY-----
";

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(verifier) = CapabilityVerifier::from_rsa_pem(
        "https://auth.fuzz.test".to_string(),
        "fuzz-broker".to_string(),
        PUBLIC_PEM.as_bytes(),
    ) else {
        return;
    };
    let store = InMemoryReplayStore::default();
    let expected = Expected::new("fuzz-subject", "fuzz-tenant", Operation::Read, b"fuzz-body");

    // Must never panic. And because the fuzzer cannot produce a valid RSA
    // signature over the pinned key, it must never succeed either — a success
    // here would mean the verifier accepted something it did not authenticate.
    if verifier.verify(token, &expected, &store).is_ok() {
        panic!("verifier accepted a capability it did not authenticate");
    }
});

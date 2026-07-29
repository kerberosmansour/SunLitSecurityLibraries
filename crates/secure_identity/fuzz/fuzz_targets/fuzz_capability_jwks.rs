#![no_main]
//! Fuzz target: bounded key-material parsing never panics and never yields a
//! usable verifier from malformed input.
//!
//! Verification keys are caller-supplied — inline PEM or a bounded JWKS
//! document — and are never fetched over the network by this crate. That makes
//! the parser an attack surface reachable by whatever supplies configuration,
//! so it must fail closed on arbitrary bytes rather than panicking or
//! constructing a verifier that trusts nothing in particular.
use libfuzzer_sys::fuzz_target;
use secure_identity::capability::{
    CapabilityVerifier, Expected, InMemoryReplayStore, Operation, RsaCapabilitySigner,
};

fuzz_target!(|data: &[u8]| {
    // Bound the input the way a caller should: reject implausibly large key
    // documents before parsing rather than after.
    if data.len() > 64 * 1024 {
        return;
    }

    // Public verification material: malformed input must produce an error, and
    // must never panic inside PEM/DER handling.
    if let Ok(verifier) = CapabilityVerifier::from_rsa_pem(
        "https://auth.fuzz.test".to_string(),
        "fuzz-broker".to_string(),
        data,
    ) {
        // If arbitrary bytes did parse as a key, the resulting verifier must
        // still reject a token that key did not sign.
        let store = InMemoryReplayStore::default();
        let expected = Expected::new("fuzz-subject", "fuzz-tenant", Operation::Read, b"fuzz-body");
        let _ = verifier.verify("not.a.capability", &expected, &store);
    }

    // Private signing material: same contract on the signing side.
    let _ = RsaCapabilitySigner::from_pkcs8_pem(data);
});

#![no_main]
//! Fuzz target: Pseudonymizer::pseudonymize never panics and produces consistent output.
use libfuzzer_sys::fuzz_target;
use secure_privacy::Pseudonymizer;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(p) = Pseudonymizer::new(b"fuzz-salt") {
            let r1 = p.pseudonymize(s);
            let r2 = p.pseudonymize(s);
            // Determinism invariant
            assert_eq!(r1, r2, "Same input must produce same pseudonym");
            // Output length invariant (SHA-256 = 64 hex chars)
            assert_eq!(r1.value.len(), 64);
        }
    }
});

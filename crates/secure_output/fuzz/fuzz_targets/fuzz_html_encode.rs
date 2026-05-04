#![no_main]
//! Fuzz target: HTML encoder never panics and never emits raw dangerous chars.
use libfuzzer_sys::fuzz_target;
use secure_output::encode::OutputEncoder;
use secure_output::html::HtmlEncoder;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let enc = HtmlEncoder;
        let encoded = enc.encode(s);
        // Invariant: no raw dangerous characters in output
        assert!(!encoded.contains('<'));
        assert!(!encoded.contains('>'));
        assert!(!encoded.contains('"'));
        assert!(!encoded.contains('\''));
    }
});

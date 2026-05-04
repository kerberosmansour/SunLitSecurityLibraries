#![no_main]
//! Fuzz target: sanitize_for_text_sink never panics and never emits raw newlines.
use libfuzzer_sys::fuzz_target;
use security_events::sanitize::sanitize_for_text_sink;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let sanitized = sanitize_for_text_sink(s);
        // Invariant: output never contains raw newline or carriage return
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
    }
});

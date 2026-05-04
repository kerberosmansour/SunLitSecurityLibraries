#![no_main]
//! Fuzz target: CertPinValidator::validate_der never panics on arbitrary DER bytes.
use libfuzzer_sys::fuzz_target;
use secure_network::{CertPinValidator, PinSet};

fuzz_target!(|data: &[u8]| {
    let mut pin_set = PinSet::new();
    pin_set.add_pin([0xAA; 32]);
    let validator = CertPinValidator::new(pin_set);
    let _ = validator.validate_der(data);
});

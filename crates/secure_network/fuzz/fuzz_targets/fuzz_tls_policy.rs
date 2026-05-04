#![no_main]
//! Fuzz target: TlsPolicy::validate never panics on arbitrary version/cipher combos.
use libfuzzer_sys::fuzz_target;
use secure_network::{CipherSuite, TlsPolicy, TlsVersion};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let min_version = match data[0] % 5 {
        0 => TlsVersion::Ssl3,
        1 => TlsVersion::Tls10,
        2 => TlsVersion::Tls11,
        3 => TlsVersion::Tls12,
        _ => TlsVersion::Tls13,
    };
    let actual_version = match data[1] % 5 {
        0 => TlsVersion::Ssl3,
        1 => TlsVersion::Tls10,
        2 => TlsVersion::Tls11,
        3 => TlsVersion::Tls12,
        _ => TlsVersion::Tls13,
    };
    let cipher = match data[2] % 9 {
        0 => CipherSuite::Aes128Gcm,
        1 => CipherSuite::Aes256Gcm,
        2 => CipherSuite::Chacha20Poly1305,
        3 => CipherSuite::Aes128Cbc,
        4 => CipherSuite::Aes256Cbc,
        5 => CipherSuite::Rc4,
        6 => CipherSuite::Des,
        7 => CipherSuite::Null,
        _ => {
            let name = std::str::from_utf8(&data[3..]).unwrap_or("unknown");
            CipherSuite::Other(name.to_string())
        }
    };

    let policy = TlsPolicy::new(min_version);
    let _ = policy.validate(actual_version, &cipher);
});

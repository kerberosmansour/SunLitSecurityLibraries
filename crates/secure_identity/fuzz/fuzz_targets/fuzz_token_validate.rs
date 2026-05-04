#![no_main]
//! Fuzz target: token validation never panics on arbitrary input.
use libfuzzer_sys::fuzz_target;
use secure_identity::authenticator::{AuthenticationRequest, Authenticator, TokenKind};
use secure_identity::token::{TokenValidator, TokenValidatorConfig};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let validator = TokenValidator::new(TokenValidatorConfig {
            issuer: "fuzz-issuer".to_string(),
            audience: "fuzz-audience".to_string(),
            secret: b"fuzz-secret-key-32-bytes-minimum!".to_vec(),
        });
        let request = AuthenticationRequest {
            token: s.to_string(),
            token_kind: TokenKind::BearerJwt,
        };
        // Must never panic — only return Ok or Err
        let _ = rt.block_on(validator.authenticate(&request));
    }
});

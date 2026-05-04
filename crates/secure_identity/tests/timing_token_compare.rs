//! Timing side-channel test — token validation timing must not diverge catastrophically.
//!
//! Milestone 9 — BDD: Token comparison constant-time.
//!
//! Marked `#[ignore]` for CI — timing tests require a stable, low-noise environment.
//! Run locally with:
//!   cargo test -p secure_identity -- timing_ --ignored
use secure_identity::{
    authenticator::{AuthenticationRequest, Authenticator, TokenKind},
    token::{TokenValidator, TokenValidatorConfig},
};
use std::time::Instant;

const SAMPLE_COUNT: usize = 200;
const SECRET: &[u8] = b"test-secret-key-for-timing-test-only-32b";

fn make_validator() -> TokenValidator {
    TokenValidator::new(TokenValidatorConfig {
        issuer: "test-issuer".to_string(),
        audience: "test-audience".to_string(),
        secret: SECRET.to_vec(),
    })
}

fn make_request(token: &str) -> AuthenticationRequest {
    AuthenticationRequest {
        token: token.to_string(),
        token_kind: TokenKind::BearerJwt,
    }
}

/// Welch's t-test statistic for two independent samples.
/// Returns the absolute t-value. Higher values indicate more significant timing difference.
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

/// Timing test: validates that JWT validation does not have a catastrophically obvious
/// timing difference between structurally different invalid tokens.
///
/// This test uses Welch's t-test to check for timing leaks. A t-value above 4.5 would
/// indicate a detectable timing difference large enough to be concerning.
///
/// Real constant-time HMAC comparison is enforced by the underlying `ring` / `jsonwebtoken`
/// library. This test catches catastrophic regressions (e.g. early-exit on first byte).
///
/// Marked `#[ignore]` — run on a quiet machine only.
#[test]
#[ignore = "timing test — run locally on a stable machine: cargo test -p secure_identity -- timing_ --ignored"]
fn timing_token_validation_no_significant_difference() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let validator = make_validator();

    // Invalid token with minimal length (format rejection path)
    let short_invalid = "not.a.jwt";
    // Invalid token with valid JWT structure but wrong signature (crypto rejection path)
    let long_invalid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                        eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoidGVzdC1pc3N1ZXIiLCJhdWQiOiJ0ZXN0LWF1ZGllbmNlIn0.\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Warm-up phase
    for _ in 0..20 {
        let req = make_request(short_invalid);
        let _ = rt.block_on(validator.authenticate(&req));
        let req = make_request(long_invalid);
        let _ = rt.block_on(validator.authenticate(&req));
    }

    let mut short_times = Vec::with_capacity(SAMPLE_COUNT);
    let mut long_times = Vec::with_capacity(SAMPLE_COUNT);

    for _ in 0..SAMPLE_COUNT {
        let req = make_request(short_invalid);
        let start = Instant::now();
        let _ = rt.block_on(validator.authenticate(&req));
        short_times.push(start.elapsed().as_nanos() as f64);

        let req = make_request(long_invalid);
        let start = Instant::now();
        let _ = rt.block_on(validator.authenticate(&req));
        long_times.push(start.elapsed().as_nanos() as f64);
    }

    let t = welchs_t(&short_times, &long_times);
    // A t-value below 4.5 means no statistically significant timing difference
    // at a meaningful level. Anything above 4.5 could indicate a timing oracle.
    assert!(
        t < 4.5,
        "Suspicious timing difference (Welch's t={t:.2}) between short and long invalid tokens. \
         This may indicate a timing side-channel. Check for early-exit logic in token validation."
    );
}

//! BDD tests for Milestone 24 TOTP MFA support.

use secure_identity::totp::TotpProvider;

#[tokio::test]
async fn scenario_valid_totp_accepted() {
    let provider = TotpProvider::new("SunLit", 1);
    let enrollment = provider
        .generate_secret("alice@example.com")
        .expect("secret generation should succeed");

    let code = provider
        .generate_current_code(&enrollment.secret)
        .expect("current code generation should succeed");

    let ok = provider
        .verify_code(&enrollment.secret, &code)
        .expect("verification should succeed");

    assert!(ok);
}

#[tokio::test]
async fn scenario_wrong_code_rejected() {
    let provider = TotpProvider::new("SunLit", 1);
    let enrollment = provider
        .generate_secret("alice@example.com")
        .expect("secret generation should succeed");

    let ok = provider
        .verify_code(&enrollment.secret, "000000")
        .expect("verification should succeed");

    assert!(!ok);
}

#[tokio::test]
async fn scenario_secret_is_redacted_in_debug_output() {
    let provider = TotpProvider::new("SunLit", 1);
    let enrollment = provider
        .generate_secret("alice@example.com")
        .expect("secret generation should succeed");

    let debug = format!("{:?}", enrollment.secret);
    assert!(debug.contains("[REDACTED]"));
}

#[tokio::test]
async fn scenario_provisioning_uri_is_generated() {
    let provider = TotpProvider::new("SunLit", 1);
    let enrollment = provider
        .generate_secret("alice@example.com")
        .expect("secret generation should succeed");

    assert!(enrollment.provisioning_uri.starts_with("otpauth://totp/"));
}

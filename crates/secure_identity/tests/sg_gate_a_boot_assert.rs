//! BDD: `assert_no_dev_identity_in_production` — sg-gate-a M4 A4.

use secure_identity::boot::{assert_no_dev_identity_in_production, ProductionModeViolation};

#[test]
fn staging_allows_dev_source() {
    // Given: staging env with a dev source present
    // When: asserted
    // Then: Ok (no production check triggered)
    assert!(assert_no_dev_identity_in_production("staging", true).is_ok());
}

#[test]
fn production_rejects_dev_source() {
    // Given: production env with a dev source present
    // When: asserted
    // Then: Err(ProductionModeViolation)
    let result = assert_no_dev_identity_in_production("production", true);
    match result {
        Err(ProductionModeViolation { .. }) => {}
        Ok(()) => panic!("expected Err(ProductionModeViolation) but got Ok"),
    }
}

#[test]
fn production_allows_no_dev_source() {
    assert!(assert_no_dev_identity_in_production("production", false).is_ok());
}

#[test]
fn development_env_no_check() {
    // Dev env never triggers the check regardless of sources.
    assert!(assert_no_dev_identity_in_production("development", true).is_ok());
    assert!(assert_no_dev_identity_in_production("development", false).is_ok());
}

#[test]
fn empty_app_env_no_check() {
    // An unset APP_ENV should not panic / not trigger the check.
    assert!(assert_no_dev_identity_in_production("", true).is_ok());
}

#[test]
fn production_error_is_displayable() {
    let err = assert_no_dev_identity_in_production("production", true).unwrap_err();
    let display = err.to_string();
    assert!(
        display.contains("production") || display.contains("dev"),
        "ProductionModeViolation display is uninformative: {display}"
    );
}

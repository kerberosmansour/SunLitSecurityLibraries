//! Boot-time security invariants.
//!
//! A service calls these helpers once, during startup, before opening its
//! listening socket. They panic or return `Err` on misconfiguration so the
//! service fails closed rather than serving requests with a dev identity
//! source active in production.

use std::fmt;

/// Production-mode misconfiguration — a dev-mode identity source is
/// registered while `APP_ENV` is set to `"production"`.
///
/// Returned by [`assert_no_dev_identity_in_production`]. Implements
/// [`std::error::Error`] + [`fmt::Display`] so services can log it or
/// convert it to a panic message.
///
/// # Examples
///
/// ```
/// use secure_identity::boot::{
///     assert_no_dev_identity_in_production, ProductionModeViolation,
/// };
///
/// let err: ProductionModeViolation =
///     assert_no_dev_identity_in_production("production", true).unwrap_err();
/// assert!(err.to_string().contains("production"));
/// ```
#[derive(Debug, Clone)]
pub struct ProductionModeViolation {
    /// The `app_env` value that triggered the violation.
    pub app_env: String,
    /// A stable, log-safe message identifying the violation.
    pub message: &'static str,
}

impl fmt::Display for ProductionModeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "production mode violation: {} (app_env={:?})",
            self.message, self.app_env
        )
    }
}

impl std::error::Error for ProductionModeViolation {}

/// Asserts no dev-mode identity source is registered when `app_env ==
/// "production"`.
///
/// Call this at service boot (before the listener starts) so
/// misconfigurations fail closed. The caller is responsible for knowing
/// whether any dev-mode identity source is registered in the validator
/// chain — pass `true` if any of:
///
/// - `DevAuthenticator` (from [`crate::dev`]) is registered,
/// - a `DevBearerSource` fixture is active,
/// - any other component that bypasses real credential validation is
///   wired into the request path.
///
/// # Errors
///
/// Returns [`ProductionModeViolation`] if `app_env == "production"` and
/// `has_dev_identity_source == true`.
///
/// # Examples
///
/// ```
/// use secure_identity::boot::assert_no_dev_identity_in_production;
///
/// // Staging with dev identity is fine.
/// assert!(assert_no_dev_identity_in_production("staging", true).is_ok());
///
/// // Production without dev identity is fine.
/// assert!(assert_no_dev_identity_in_production("production", false).is_ok());
///
/// // Production WITH dev identity is a violation.
/// assert!(assert_no_dev_identity_in_production("production", true).is_err());
/// ```
///
/// Typical boot wiring:
///
/// ```no_run
/// use secure_identity::boot::assert_no_dev_identity_in_production;
///
/// let app_env = std::env::var("APP_ENV").unwrap_or_default();
/// let has_dev = cfg!(feature = "dev"); // or your own detection
///
/// if let Err(violation) = assert_no_dev_identity_in_production(&app_env, has_dev) {
///     panic!("{violation}");
/// }
/// ```
pub fn assert_no_dev_identity_in_production(
    app_env: &str,
    has_dev_identity_source: bool,
) -> Result<(), ProductionModeViolation> {
    if app_env == "production" && has_dev_identity_source {
        return Err(ProductionModeViolation {
            app_env: app_env.to_owned(),
            message: "dev identity source registered while APP_ENV=production",
        });
    }
    Ok(())
}

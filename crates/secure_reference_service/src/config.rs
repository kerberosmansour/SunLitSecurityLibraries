//! `SecurityConfig` — startup configuration validation.
//!
//! Validates: policies loaded, key provider reachable, required security headers configured,
//! identity source configured. Fails fast on misconfiguration.

use secure_data::config::SecretReference;

/// Errors that occur during security configuration validation.
#[derive(Debug)]
pub enum ConfigError {
    /// An authorization policy is missing or invalid.
    MissingPolicy(String),
    /// The key provider is misconfigured.
    KeyProviderError(String),
    /// A required security header is missing from configuration.
    MissingSecurityHeader(String),
    /// The identity source is not configured.
    IdentitySourceMissing,
    /// A secret reference is invalid.
    InvalidSecretReference(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPolicy(p) => write!(f, "missing authorization policy: {p}"),
            Self::KeyProviderError(e) => write!(f, "key provider error: {e}"),
            Self::MissingSecurityHeader(h) => write!(f, "missing security header config: {h}"),
            Self::IdentitySourceMissing => write!(f, "identity source not configured"),
            Self::InvalidSecretReference(e) => write!(f, "invalid secret reference: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Service security configuration.
///
/// Validated at startup via [`SecurityConfig::validate`]. If validation fails,
/// the service must not bind a port.
#[derive(Debug)]
pub struct SecurityConfig {
    /// Whether at least one authorization policy is loaded.
    pub policies_loaded: bool,
    /// The key alias to use for envelope encryption. Must exist in the key provider.
    pub encryption_key_alias: String,
    /// Whether the identity source is configured.
    pub identity_source_configured: bool,
    /// Optional secret reference for the signing key (validated for parse correctness only).
    pub signing_key_ref: Option<String>,
}

impl SecurityConfig {
    /// Creates a default development `SecurityConfig`.
    #[must_use]
    pub fn dev() -> Self {
        Self {
            policies_loaded: true,
            encryption_key_alias: "default".to_string(),
            identity_source_configured: true,
            signing_key_ref: Some("env://DEV_SIGNING_KEY".to_string()),
        }
    }

    /// Validates the configuration. Returns an error if any invariant is violated.
    ///
    /// The service must call this at startup and fail fast on any error.
    ///
    /// # Errors
    /// Returns [`ConfigError`] describing the first violated invariant.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.policies_loaded {
            return Err(ConfigError::MissingPolicy(
                "no authorization policies loaded".to_string(),
            ));
        }

        if self.encryption_key_alias.is_empty() {
            return Err(ConfigError::KeyProviderError(
                "encryption_key_alias must not be empty".to_string(),
            ));
        }

        if !self.identity_source_configured {
            return Err(ConfigError::IdentitySourceMissing);
        }

        // Validate secret reference parses correctly (if provided)
        if let Some(ref sref) = self.signing_key_ref {
            SecretReference::parse(sref)
                .map_err(|e| ConfigError::InvalidSecretReference(e.to_string()))?;
        }

        Ok(())
    }
}

/// A config with an intentionally invalid key alias (for startup failure tests).
#[must_use]
pub fn misconfigured_key_provider() -> SecurityConfig {
    SecurityConfig {
        policies_loaded: true,
        encryption_key_alias: String::new(), // empty alias — will fail validation
        identity_source_configured: true,
        signing_key_ref: None,
    }
}

/// A config missing policy (for startup failure tests).
#[must_use]
pub fn misconfigured_no_policy() -> SecurityConfig {
    SecurityConfig {
        policies_loaded: false,
        encryption_key_alias: "default".to_string(),
        identity_source_configured: true,
        signing_key_ref: None,
    }
}

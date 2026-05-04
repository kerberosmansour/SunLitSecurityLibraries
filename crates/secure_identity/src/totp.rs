//! RFC 6238 time-based one-time password (TOTP) support.

use std::collections::HashMap;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::Mutex;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use crate::error::IdentityError;
use crate::mfa::{MfaChallenge, MfaChallengeKind, MfaProvider, MfaResponse};

/// A redacted string wrapper for TOTP secrets.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    /// Creates a new secret wrapper from raw string data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::totp::SecretString;
    ///
    /// let secret = SecretString::new("BASE32SECRET".to_string());
    /// assert_eq!(secret.expose_secret(), "BASE32SECRET");
    /// ```
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Exposes the wrapped secret value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::totp::SecretString;
    ///
    /// let secret = SecretString::new("BASE32SECRET".to_string());
    /// assert_eq!(secret.expose_secret(), "BASE32SECRET");
    /// ```
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

/// Enrollment data returned when setting up TOTP.
#[derive(Debug, Clone)]
pub struct TotpEnrollment {
    /// Shared secret used for code generation.
    pub secret: SecretString,
    /// Provisioning URI suitable for authenticator applications.
    pub provisioning_uri: String,
}

/// TOTP provider implementing RFC 6238 with SHA-1 (compatibility-first default).
pub struct TotpProvider {
    issuer: String,
    skew: u8,
    challenges: Mutex<HashMap<String, SecretString>>,
}

impl TotpProvider {
    /// Creates a provider with the given issuer and allowed clock skew (steps).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::totp::TotpProvider;
    ///
    /// let provider = TotpProvider::new("SunLit", 1);
    /// let _ = provider;
    /// ```
    #[must_use]
    pub fn new(issuer: impl Into<String>, skew: u8) -> Self {
        Self {
            issuer: issuer.into(),
            skew,
            challenges: Mutex::new(HashMap::new()),
        }
    }

    /// Generates a new TOTP secret and provisioning URI for an account.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::totp::TotpProvider;
    ///
    /// let provider = TotpProvider::new("SunLit", 1);
    /// let enrollment = provider.generate_secret("alice@example.com")?;
    /// assert!(enrollment.provisioning_uri.starts_with("otpauth://totp/"));
    /// # Ok::<(), secure_identity::IdentityError>(())
    /// ```
    pub fn generate_secret(&self, account_name: &str) -> Result<TotpEnrollment, IdentityError> {
        let rng = SystemRandom::new();
        let mut bytes = [0_u8; 20];
        rng.fill(&mut bytes)
            .map_err(|_| IdentityError::ProviderUnavailable)?;

        let secret = match Secret::Raw(bytes.to_vec()).to_encoded() {
            Secret::Encoded(value) => value,
            Secret::Raw(_) => return Err(IdentityError::ProviderUnavailable),
        };
        let secret = SecretString::new(secret);

        let totp = self.build_totp(secret_bytes(secret.expose_secret())?, account_name)?;

        Ok(TotpEnrollment {
            secret,
            provisioning_uri: totp.get_url(),
        })
    }

    /// Generates the current six-digit TOTP code for a secret.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::totp::TotpProvider;
    ///
    /// let provider = TotpProvider::new("SunLit", 1);
    /// let enrollment = provider.generate_secret("alice@example.com")?;
    /// let code = provider.generate_current_code(&enrollment.secret)?;
    /// assert_eq!(code.len(), 6);
    /// # Ok::<(), secure_identity::IdentityError>(())
    /// ```
    pub fn generate_current_code(&self, secret: &SecretString) -> Result<String, IdentityError> {
        let totp = self.build_totp(secret_bytes(secret.expose_secret())?, "user")?;
        totp.generate_current()
            .map_err(|_| IdentityError::ProviderUnavailable)
    }

    /// Verifies a user-provided TOTP code for the current time window.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::totp::TotpProvider;
    ///
    /// let provider = TotpProvider::new("SunLit", 1);
    /// let enrollment = provider.generate_secret("alice@example.com")?;
    /// let code = provider.generate_current_code(&enrollment.secret)?;
    /// assert!(provider.verify_code(&enrollment.secret, &code)?);
    /// # Ok::<(), secure_identity::IdentityError>(())
    /// ```
    pub fn verify_code(&self, secret: &SecretString, code: &str) -> Result<bool, IdentityError> {
        let totp = self.build_totp(secret_bytes(secret.expose_secret())?, "user")?;
        totp.check_current(code)
            .map_err(|_| IdentityError::ProviderUnavailable)
    }

    fn build_totp(&self, secret: Vec<u8>, account_name: &str) -> Result<TOTP, IdentityError> {
        TOTP::new(
            Algorithm::SHA1,
            6,
            self.skew,
            30,
            secret,
            Some(self.issuer.clone()),
            account_name.to_owned(),
        )
        .map_err(|_| IdentityError::ProviderUnavailable)
    }
}

fn secret_bytes(secret: &str) -> Result<Vec<u8>, IdentityError> {
    Secret::Encoded(secret.to_owned())
        .to_bytes()
        .map_err(|_| IdentityError::InvalidCredentials)
}

impl Default for TotpProvider {
    fn default() -> Self {
        Self::new("SunLit", 1)
    }
}

impl MfaProvider for TotpProvider {
    async fn issue_challenge(&self, actor_id: &str) -> Result<MfaChallenge, IdentityError> {
        let enrollment = self.generate_secret(actor_id)?;
        let challenge_id = Uuid::new_v4().to_string();
        self.challenges
            .lock()
            .await
            .insert(challenge_id.clone(), enrollment.secret);

        Ok(MfaChallenge {
            challenge_id,
            kind: MfaChallengeKind::Totp,
        })
    }

    async fn verify_response(&self, response: &MfaResponse) -> Result<bool, IdentityError> {
        let secret = self
            .challenges
            .lock()
            .await
            .get(&response.challenge_id)
            .cloned()
            .ok_or(IdentityError::InvalidCredentials)?;

        self.verify_code(&secret, &response.code)
    }
}

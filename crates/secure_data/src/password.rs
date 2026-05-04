//! Password hashing and verification — Argon2id default (OWASP C2/C7).
//!
//! Provides production-grade password hashing via the [`hash_password()`](crate::password::hash_password) and
//! [`verify_password()`](crate::password::verify_password) convenience functions, backed by the Argon2id algorithm.
//! The [`PasswordHasher`](crate::password::PasswordHasher) trait allows swapping algorithm implementations.
//!
//! # Examples
//!
//! ```
//! use secure_data::password::{hash_password, verify_password};
//! use secure_data::secret::SecretString;
//!
//! let password = SecretString::new("correct-horse-battery".to_string());
//! let hash = hash_password(&password).unwrap();
//! assert!(verify_password(&password, &hash).unwrap());
//! ```

use crate::secret::SecretString;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash as Argon2PasswordHash, PasswordVerifier, SaltString};
use argon2::{Argon2, PasswordHasher as Argon2PasswordHasher};
use serde::Serializer;
use zeroize::Zeroizing;

/// Errors that can occur during password hashing or verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordError {
    /// The provided password was empty.
    #[error("empty password")]
    EmptyPassword,

    /// The hashing algorithm failed internally.
    #[error("hashing failed: {reason}")]
    HashingFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// The stored hash string is not valid PHC format.
    #[error("invalid hash format: {reason}")]
    InvalidHashFormat {
        /// Human-readable reason for the parse failure.
        reason: String,
    },
}

/// A hashed password stored in [PHC string format].
///
/// This type:
/// - Redacts its content in [`Debug`] and [`Serialize`](serde::Serialize) output
///   to prevent accidental exposure.
/// - Zeroizes the inner hash string on drop.
/// - Provides [`expose_hash()`](PasswordHash::expose_hash) for controlled access
///   to the raw PHC string.
///
/// [PHC string format]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
///
/// # Examples
///
/// ```
/// use secure_data::password::hash_password;
/// use secure_data::secret::SecretString;
///
/// let hash = hash_password(&SecretString::new("my-password".to_string())).unwrap();
/// // Debug output is redacted:
/// assert!(format!("{:?}", hash).contains("[REDACTED]"));
/// // Access the raw PHC string when needed:
/// assert!(hash.expose_hash().starts_with("$argon2id$"));
/// ```
#[must_use]
pub struct PasswordHash {
    inner: Zeroizing<String>,
}

impl PasswordHash {
    /// Creates a new [`PasswordHash`] from a PHC string.
    pub(crate) fn new(phc_string: String) -> Self {
        Self {
            inner: Zeroizing::new(phc_string),
        }
    }

    /// Returns the raw PHC hash string.
    ///
    /// Use this only when you need to persist the hash (e.g., to a database).
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_data::password::hash_password;
    /// use secure_data::secret::SecretString;
    ///
    /// let hash = hash_password(&SecretString::new("pw".to_string())).unwrap();
    /// let phc = hash.expose_hash();
    /// assert!(phc.starts_with("$argon2id$"));
    /// ```
    #[must_use]
    pub fn expose_hash(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PasswordHash([REDACTED])")
    }
}

impl Clone for PasswordHash {
    fn clone(&self) -> Self {
        Self {
            inner: Zeroizing::new((*self.inner).clone()),
        }
    }
}

impl serde::Serialize for PasswordHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

/// Trait for password hashing algorithms.
///
/// Implement this trait to provide a custom password hashing backend.
/// The default implementation is [`Argon2Hasher`], which uses Argon2id.
///
/// # Examples
///
/// ```
/// use secure_data::password::{Argon2Hasher, PasswordHasher};
/// use secure_data::secret::SecretString;
///
/// let hasher = Argon2Hasher::default();
/// let password = SecretString::new("my-password".to_string());
/// let hash = hasher.hash_password(&password).unwrap();
/// assert!(hasher.verify_password(&password, &hash).unwrap());
/// ```
pub trait PasswordHasher: Send + Sync {
    /// Hash a password, returning a [`PasswordHash`] in PHC string format.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::EmptyPassword`] if the password is empty.
    /// Returns [`PasswordError::HashingFailed`] if the algorithm fails internally.
    fn hash_password(&self, password: &SecretString) -> Result<PasswordHash, PasswordError>;

    /// Verify a password against a stored hash.
    ///
    /// Returns `Ok(true)` if the password matches, `Ok(false)` if it does not.
    /// Uses constant-time comparison internally.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::InvalidHashFormat`] if the stored hash cannot be parsed.
    fn verify_password(
        &self,
        password: &SecretString,
        hash: &PasswordHash,
    ) -> Result<bool, PasswordError>;
}

/// Argon2id password hasher with OWASP-recommended defaults.
///
/// Uses the Argon2id variant with parameters suitable for server-side
/// password hashing. The defaults follow OWASP recommendations: Argon2id
/// with memory cost 19 MiB, iteration count 2, parallelism 1.
///
/// # Examples
///
/// ```
/// use secure_data::password::{Argon2Hasher, PasswordHasher};
/// use secure_data::secret::SecretString;
///
/// let hasher = Argon2Hasher::default();
/// let password = SecretString::new("correct-horse-battery".to_string());
/// let hash = hasher.hash_password(&password).unwrap();
/// assert!(hasher.verify_password(&password, &hash).unwrap());
/// ```
#[derive(Debug, Clone, Default)]
pub struct Argon2Hasher {
    _private: (),
}

impl PasswordHasher for Argon2Hasher {
    fn hash_password(&self, password: &SecretString) -> Result<PasswordHash, PasswordError> {
        let plaintext = password.expose_secret();
        if plaintext.is_empty() {
            return Err(PasswordError::EmptyPassword);
        }

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(plaintext.as_bytes(), &salt)
            .map_err(|e| PasswordError::HashingFailed {
                reason: e.to_string(),
            })?;

        Ok(PasswordHash::new(hash.to_string()))
    }

    fn verify_password(
        &self,
        password: &SecretString,
        hash: &PasswordHash,
    ) -> Result<bool, PasswordError> {
        let parsed = Argon2PasswordHash::new(hash.expose_hash()).map_err(|e| {
            PasswordError::InvalidHashFormat {
                reason: e.to_string(),
            }
        })?;

        let argon2 = Argon2::default();
        match argon2.verify_password(password.expose_secret().as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(PasswordError::HashingFailed {
                reason: e.to_string(),
            }),
        }
    }
}

/// Hashes a password using Argon2id with secure defaults.
///
/// This is the primary API for password hashing. It creates a random salt
/// and hashes the password using Argon2id with OWASP-recommended parameters.
///
/// # Examples
///
/// ```
/// use secure_data::password::hash_password;
/// use secure_data::secret::SecretString;
///
/// let password = SecretString::new("correct-horse-battery".to_string());
/// let hash = hash_password(&password).unwrap();
/// assert!(hash.expose_hash().starts_with("$argon2id$"));
/// ```
///
/// # Errors
///
/// Returns [`PasswordError::EmptyPassword`] if the password is empty.
/// Returns [`PasswordError::HashingFailed`] if the algorithm fails.
pub fn hash_password(password: &SecretString) -> Result<PasswordHash, PasswordError> {
    Argon2Hasher::default().hash_password(password)
}

/// Verifies a password against a stored Argon2id hash.
///
/// Returns `Ok(true)` if the password matches, `Ok(false)` otherwise.
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Examples
///
/// ```
/// use secure_data::password::{hash_password, verify_password};
/// use secure_data::secret::SecretString;
///
/// let password = SecretString::new("correct-horse-battery".to_string());
/// let hash = hash_password(&password).unwrap();
/// assert!(verify_password(&password, &hash).unwrap());
///
/// let wrong = SecretString::new("wrong-password".to_string());
/// assert!(!verify_password(&wrong, &hash).unwrap());
/// ```
///
/// # Errors
///
/// Returns [`PasswordError::InvalidHashFormat`] if the hash string cannot be parsed.
pub fn verify_password(
    password: &SecretString,
    hash: &PasswordHash,
) -> Result<bool, PasswordError> {
    Argon2Hasher::default().verify_password(password, hash)
}

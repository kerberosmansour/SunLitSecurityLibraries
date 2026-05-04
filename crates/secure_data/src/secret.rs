// Secret wrapper types for secure_data.
//
// These types ensure secrets never leak via Debug, Display, or default Serde.
// All wrappers use zeroize to clear memory on drop.

use serde::Serializer;
use zeroize::Zeroizing;

/// A secret string value that suppresses Debug output and serializes as `"\[REDACTED\]"`.
///
/// Use `expose_secret()` to access the inner value — only where strictly necessary.
///
/// # Examples
///
/// ```
/// use secure_data::secret::SecretString;
///
/// let secret = SecretString::new("my-api-key".to_string());
/// assert_eq!(secret.expose_secret(), "my-api-key");
/// // Debug output is redacted:
/// assert!(format!("{:?}", secret).contains("REDACTED"));
/// ```
pub struct SecretString {
    inner: Zeroizing<String>,
}

impl SecretString {
    /// Creates a new `SecretString` wrapping the given value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    /// Exposes the secret value — use only where strictly necessary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

impl serde::Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

/// A secret byte buffer that suppresses Debug output and zeroes memory on drop.
///
/// # Examples
///
/// ```
/// use secure_data::secret::SecretBytes;
///
/// let secret = SecretBytes::new(vec![0x01, 0x02, 0x03]);
/// assert_eq!(secret.expose_secret(), &[0x01, 0x02, 0x03]);
/// assert!(format!("{:?}", secret).contains("REDACTED"));
/// ```
pub struct SecretBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    /// Creates a new `SecretBytes` wrapping the given value.
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    /// Exposes the secret bytes — use only where strictly necessary.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.inner
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED] {} bytes)", self.inner.len())
    }
}

impl serde::Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

/// A typed API token wrapper.
///
/// # Examples
///
/// ```
/// use secure_data::secret::ApiToken;
///
/// let token = ApiToken::new("example-api-token".to_string());
/// assert_eq!(token.expose_secret(), "example-api-token");
/// ```
pub struct ApiToken {
    inner: Zeroizing<String>,
}

impl ApiToken {
    /// Creates a new `ApiToken`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    /// Exposes the token value.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApiToken([REDACTED])")
    }
}

/// A typed database password wrapper.
///
/// # Examples
///
/// ```
/// use secure_data::secret::DbPassword;
///
/// let pw = DbPassword::new("s3cret".to_string());
/// assert_eq!(pw.expose_secret(), "s3cret");
/// ```
pub struct DbPassword {
    inner: Zeroizing<String>,
}

impl DbPassword {
    /// Creates a new `DbPassword`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    /// Exposes the password value.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Debug for DbPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DbPassword([REDACTED])")
    }
}

/// A reference to a signing key (alias, not the raw key material).
///
/// # Examples
///
/// ```
/// use secure_data::secret::SigningKeyRef;
///
/// let key_ref = SigningKeyRef::new("prod-signing-key-v2".to_string());
/// assert_eq!(key_ref.expose_secret(), "prod-signing-key-v2");
/// ```
pub struct SigningKeyRef {
    inner: Zeroizing<String>,
}

impl SigningKeyRef {
    /// Creates a new `SigningKeyRef`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self {
            inner: Zeroizing::new(value),
        }
    }

    /// Exposes the key reference value.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }
}

impl std::fmt::Debug for SigningKeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyRef([REDACTED])")
    }
}

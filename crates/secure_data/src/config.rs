// Secret references in config — parse and resolve vault://, kms://, and env:// URIs.

use crate::error::DataError;

/// The backing provider for a secret reference.
///
/// # Examples
///
/// ```
/// use secure_data::config::SecretReferenceProvider;
///
/// let provider = SecretReferenceProvider::Vault;
/// assert_eq!(provider, SecretReferenceProvider::Vault);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretReferenceProvider {
    /// HashiCorp Vault / OpenBao KV store.
    Vault,
    /// AWS KMS or compatible managed key service.
    Kms,
    /// Environment variable.
    Env,
}

/// A parsed secret reference — a URI pointing to where a secret lives,
/// rather than the secret value itself.
///
/// # Examples
///
/// ```
/// use secure_data::config::{SecretReference, SecretReferenceProvider};
///
/// let r = SecretReference::parse("vault://kv/db-creds#password").unwrap();
/// assert_eq!(r.provider, SecretReferenceProvider::Vault);
/// assert_eq!(r.path, "kv/db-creds");
/// assert_eq!(r.field.as_deref(), Some("password"));
///
/// let env = SecretReference::parse("env://MY_SECRET").unwrap();
/// assert_eq!(env.provider, SecretReferenceProvider::Env);
/// ```
#[derive(Debug, Clone)]
pub struct SecretReference {
    /// The backing provider.
    pub provider: SecretReferenceProvider,
    /// The path within the provider (everything after `scheme://`, before `#`).
    pub path: String,
    /// Optional field within the path (the fragment after `#`).
    pub field: Option<String>,
}

impl SecretReference {
    /// Parses a secret reference URI string.
    ///
    /// # Errors
    /// Returns [`DataError::InvalidSecretReference`] for unrecognised schemes or malformed URIs.
    pub fn parse(input: &str) -> Result<Self, DataError> {
        if let Some(rest) = input.strip_prefix("vault://") {
            let (path, field) = split_fragment(rest);
            return Ok(SecretReference {
                provider: SecretReferenceProvider::Vault,
                path: path.to_string(),
                field: field.map(str::to_string),
            });
        }

        if let Some(rest) = input.strip_prefix("kms://") {
            let (path, field) = split_fragment(rest);
            return Ok(SecretReference {
                provider: SecretReferenceProvider::Kms,
                path: path.to_string(),
                field: field.map(str::to_string),
            });
        }

        if let Some(rest) = input.strip_prefix("env://") {
            let (path, field) = split_fragment(rest);
            return Ok(SecretReference {
                provider: SecretReferenceProvider::Env,
                path: path.to_string(),
                field: field.map(str::to_string),
            });
        }

        Err(DataError::InvalidSecretReference {
            input: input.to_string(),
        })
    }
}

/// Splits a string on the first `#`, returning `(before, Some(after))` or `(whole, None)`.
fn split_fragment(s: &str) -> (&str, Option<&str>) {
    if let Some(idx) = s.find('#') {
        (&s[..idx], Some(&s[idx + 1..]))
    } else {
        (s, None)
    }
}

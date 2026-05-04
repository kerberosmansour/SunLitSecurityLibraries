//! Identity error types.

/// Errors that may occur during identity operations.
///
/// # Examples
///
/// ```
/// use secure_identity::error::IdentityError;
///
/// let err = IdentityError::TokenExpired;
/// assert_eq!(err.to_string(), "token expired");
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityError {
    /// Wrong issuer or bad credentials.
    InvalidCredentials,
    /// The token has expired.
    TokenExpired,
    /// The token is malformed or has an invalid signature.
    TokenMalformed,
    /// MFA is required before authentication can complete.
    MfaRequired,
    /// The session has expired.
    SessionExpired,
    /// The identity provider is temporarily unavailable.
    ProviderUnavailable,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCredentials => write!(f, "invalid credentials"),
            Self::TokenExpired => write!(f, "token expired"),
            Self::TokenMalformed => write!(f, "token malformed"),
            Self::MfaRequired => write!(f, "MFA required"),
            Self::SessionExpired => write!(f, "session expired"),
            Self::ProviderUnavailable => write!(f, "identity provider unavailable"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<IdentityError> for secure_errors::kind::AppError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::InvalidCredentials => Self::Forbidden {
                policy: "invalid_credentials",
            },
            IdentityError::TokenExpired => Self::Forbidden {
                policy: "token_expired",
            },
            IdentityError::TokenMalformed => Self::Validation {
                code: "token_malformed",
            },
            IdentityError::MfaRequired => Self::Forbidden {
                policy: "mfa_required",
            },
            IdentityError::SessionExpired => Self::Forbidden {
                policy: "session_expired",
            },
            IdentityError::ProviderUnavailable => Self::Dependency {
                dep: "identity_provider",
            },
        }
    }
}

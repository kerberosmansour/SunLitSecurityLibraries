//! Authenticator trait and request/result types.

pub(crate) mod private {
    /// Sealing marker — prevents external crates from implementing [`super::Authenticator`].
    pub trait Sealed {}
}

/// The kind of authentication token.
///
/// # Examples
///
/// ```
/// use secure_identity::authenticator::TokenKind;
///
/// let kind = TokenKind::BearerJwt;
/// ```
pub enum TokenKind {
    /// A Bearer JWT token.
    BearerJwt,
    /// An API key.
    ApiKey,
    /// A session cookie.
    SessionCookie,
}

/// A request to authenticate a token.
///
/// # Examples
///
/// ```
/// use secure_identity::authenticator::{AuthenticationRequest, TokenKind};
///
/// let request = AuthenticationRequest {
///     token: "my-token".to_string(),
///     token_kind: TokenKind::BearerJwt,
/// };
/// ```
pub struct AuthenticationRequest {
    /// The raw token string.
    pub token: String,
    /// The kind of token being presented.
    pub token_kind: TokenKind,
}

/// A sealed trait for authenticating tokens.
///
/// This trait is sealed — only types within this crate can implement it.
#[allow(async_fn_in_trait)]
pub trait Authenticator: private::Sealed {
    /// Authenticates the given request and returns an [`security_core::identity::AuthenticatedIdentity`] on success.
    async fn authenticate(
        &self,
        request: &AuthenticationRequest,
    ) -> Result<security_core::identity::AuthenticatedIdentity, crate::error::IdentityError>;
}

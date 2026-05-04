//! Identity abstraction — open trait for identity-agnostic authorization.
//!
//! [`IdentitySource`] lives in `security_core` so that `secure_authz` can accept identity from
//! ANY provider (Keycloak, Auth0, `secure_identity`, custom OIDC) without depending on any
//! specific identity crate. This is the load-bearing integration point described in THREAT-S-01.

use crate::types::{ActorId, TenantId};
use std::collections::HashMap;
use std::error::Error;
use time::OffsetDateTime;

/// The authenticated identity of a resolved principal.
///
/// Produced by any [`IdentitySource`] implementation after successful token validation.
///
/// # Examples
///
/// ```
/// use security_core::identity::AuthenticatedIdentity;
/// use security_core::types::{ActorId, TenantId};
/// use uuid::Uuid;
/// use std::collections::HashMap;
/// use time::OffsetDateTime;
///
/// let identity = AuthenticatedIdentity {
///     actor_id: ActorId::from(Uuid::new_v4()),
///     tenant_id: Some(TenantId::from(Uuid::new_v4())),
///     roles: vec!["admin".to_string()],
///     attributes: HashMap::new(),
///     authenticated_at: OffsetDateTime::now_utc(),
/// };
/// assert_eq!(identity.roles.len(), 1);
/// ```
#[derive(Clone, Debug)]
pub struct AuthenticatedIdentity {
    /// The resolved actor identifier.
    pub actor_id: ActorId,
    /// The tenant the actor belongs to, if multi-tenancy applies.
    pub tenant_id: Option<TenantId>,
    /// The roles assigned to this actor.
    pub roles: Vec<String>,
    /// Arbitrary key-value attributes from the identity provider.
    pub attributes: HashMap<String, String>,
    /// The time at which the token was authenticated.
    pub authenticated_at: OffsetDateTime,
}

/// Errors that may occur when resolving an identity token.
///
/// This enum is `#[non_exhaustive]` — new variants may be added in future minor versions.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityResolutionError {
    /// The token is malformed or has an invalid signature.
    InvalidToken,
    /// The token has expired.
    Expired,
    /// The identity provider is temporarily unavailable.
    ProviderUnavailable,
    /// An unexpected error occurred.
    Other(Box<dyn Error + Send + Sync + 'static>),
}

impl std::fmt::Display for IdentityResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "invalid token"),
            Self::Expired => write!(f, "token expired"),
            Self::ProviderUnavailable => write!(f, "identity provider unavailable"),
            Self::Other(e) => write!(f, "identity resolution error: {e}"),
        }
    }
}

impl Error for IdentityResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Other(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// An open trait for resolving bearer tokens to authenticated identities.
///
/// This trait is intentionally NOT sealed — external crates (Keycloak adapters, Auth0 adapters,
/// `secure_identity`, custom OIDC implementations) must be able to implement it. Keeping it in
/// `security_core` means `secure_authz` only depends on this crate, not on any specific identity
/// provider.
///
/// # Note on `async fn` in trait
/// We intentionally use `async fn` syntax (stabilised in Rust 1.75). Implementors must ensure
/// the returned future is `Send` where needed (e.g. in multi-threaded Tokio executors).
#[allow(async_fn_in_trait)]
pub trait IdentitySource {
    /// Resolves a bearer `token` to an [`AuthenticatedIdentity`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityResolutionError`] if:
    /// - The token is malformed or has an invalid signature ([`IdentityResolutionError::InvalidToken`]).
    /// - The token has expired ([`IdentityResolutionError::Expired`]).
    /// - The identity provider is temporarily unavailable ([`IdentityResolutionError::ProviderUnavailable`]).
    async fn resolve(&self, token: &str) -> Result<AuthenticatedIdentity, IdentityResolutionError>;
}

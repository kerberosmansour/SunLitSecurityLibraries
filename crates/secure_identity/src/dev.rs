//! Development-only authenticator — NOT FOR PRODUCTION.

#[cfg(feature = "dev")]
use security_core::types::{ActorId, TenantId};

#[cfg(feature = "dev")]
use crate::authenticator::{private, AuthenticationRequest};
#[cfg(feature = "dev")]
use crate::error::IdentityError;

/// A development-only authenticator that accepts any token.
///
/// # Warning
/// This authenticator bypasses all security checks. It must never be used in production.
#[cfg(feature = "dev")]
pub struct DevAuthenticator {
    /// The actor ID to return for all requests.
    pub actor_id: ActorId,
    /// The tenant ID to return for all requests.
    pub tenant_id: Option<TenantId>,
    /// The roles to return for all requests.
    pub roles: Vec<String>,
}

#[cfg(feature = "dev")]
impl DevAuthenticator {
    /// Creates a new [`DevAuthenticator`].
    ///
    /// # Warning
    /// Logs a warning — this is not for production use.
    pub fn new(actor_id: ActorId, tenant_id: Option<TenantId>, roles: Vec<String>) -> Self {
        tracing::warn!("DevAuthenticator in use — not for production");
        Self {
            actor_id,
            tenant_id,
            roles,
        }
    }
}

#[cfg(feature = "dev")]
impl private::Sealed for DevAuthenticator {}

#[cfg(feature = "dev")]
impl crate::authenticator::Authenticator for DevAuthenticator {
    async fn authenticate(
        &self,
        _request: &AuthenticationRequest,
    ) -> Result<security_core::identity::AuthenticatedIdentity, IdentityError> {
        use std::collections::HashMap;
        use time::OffsetDateTime;

        Ok(security_core::identity::AuthenticatedIdentity {
            actor_id: self.actor_id.clone(),
            tenant_id: self.tenant_id.clone(),
            roles: self.roles.clone(),
            attributes: HashMap::new(),
            authenticated_at: OffsetDateTime::now_utc(),
        })
    }
}

//! SubjectResolver — converts `AuthenticatedIdentity` into `Subject`.
use security_core::identity::AuthenticatedIdentity;

use crate::subject::Subject;

/// Converts an [`AuthenticatedIdentity`] (from any `IdentitySource` implementor)
/// into a [`crate::subject::Subject`].
///
/// This trait is intentionally identity-agnostic — the identity may come from
/// `secure_identity`, Keycloak, Auth0, or any custom provider.
pub trait SubjectResolver {
    /// Resolves the authenticated identity to a [`crate::subject::Subject`].
    fn resolve(identity: &AuthenticatedIdentity) -> Subject;
}

/// Default implementation that maps `AuthenticatedIdentity` fields directly to `Subject`.
pub struct DefaultSubjectResolver;

impl SubjectResolver for DefaultSubjectResolver {
    fn resolve(identity: &AuthenticatedIdentity) -> Subject {
        Subject {
            actor_id: identity.actor_id.to_string(),
            tenant_id: identity.tenant_id.as_ref().map(|t| t.to_string()),
            roles: identity.roles.iter().cloned().collect(),
            attributes: identity
                .attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

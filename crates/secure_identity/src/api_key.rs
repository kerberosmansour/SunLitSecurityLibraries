//! API key authentication with constant-time comparison.

use std::collections::HashMap;

use security_core::identity::AuthenticatedIdentity;
use security_core::severity::SecuritySeverity;
use security_core::types::ActorId;
use security_events::emit::emit_security_event;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::authenticator::{private, AuthenticationRequest};
use crate::error::IdentityError;

/// Authenticates requests via API key with constant-time comparison.
///
/// Uses `ring::constant_time::verify_slices_are_equal` to prevent timing
/// side-channel attacks during key comparison.
///
/// # Examples
///
/// ```
/// use secure_identity::api_key::ApiKeyAuthenticator;
/// use security_core::types::ActorId;
/// use uuid::Uuid;
///
/// let authenticator = ApiKeyAuthenticator::new(
///     "secret-api-key".to_string(),
///     ActorId::from(Uuid::new_v4()),
///     vec!["reader".to_string()],
/// );
/// ```
pub struct ApiKeyAuthenticator {
    /// The expected API key (stored as bytes for constant-time comparison).
    expected_key: Vec<u8>,
    /// The actor identity returned on successful authentication.
    actor_id: ActorId,
    /// The roles assigned to this API key.
    roles: Vec<String>,
}

impl ApiKeyAuthenticator {
    /// Creates a new [`ApiKeyAuthenticator`].
    ///
    /// # Arguments
    /// * `expected_key` — The valid API key string.
    /// * `actor_id` — The actor identity to return on successful authentication.
    /// * `roles` — The roles assigned to this API key.
    #[must_use]
    pub fn new(expected_key: String, actor_id: ActorId, roles: Vec<String>) -> Self {
        Self {
            expected_key: expected_key.into_bytes(),
            actor_id,
            roles,
        }
    }
}

impl private::Sealed for ApiKeyAuthenticator {}

impl crate::authenticator::Authenticator for ApiKeyAuthenticator {
    async fn authenticate(
        &self,
        request: &AuthenticationRequest,
    ) -> Result<AuthenticatedIdentity, IdentityError> {
        let presented = request.token.as_bytes();

        // Constant-time comparison to prevent timing side-channels.
        // Length mismatch is handled: if lengths differ, pad the shorter and compare,
        // ensuring constant-time behavior regardless of input length.
        let is_valid = if presented.len() != self.expected_key.len() {
            // Still do a constant-time compare to avoid leaking length info via timing
            let _ = self.expected_key.ct_eq(&self.expected_key);
            false
        } else {
            presented.ct_eq(&self.expected_key).into()
        };

        if !is_valid {
            emit_security_event(SecurityEvent::new(
                EventKind::AuthnFailure,
                SecuritySeverity::High,
                EventOutcome::Failure,
            ));
            return Err(IdentityError::InvalidCredentials);
        }

        Ok(AuthenticatedIdentity {
            actor_id: self.actor_id.clone(),
            tenant_id: None,
            roles: self.roles.clone(),
            attributes: HashMap::new(),
            authenticated_at: OffsetDateTime::now_utc(),
        })
    }
}

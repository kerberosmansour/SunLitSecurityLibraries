//! Session management trait and types.

use std::collections::HashMap;

use ring::rand::{SecureRandom, SystemRandom};
use security_core::identity::AuthenticatedIdentity;
use security_core::types::{ActorId, TenantId};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::error::IdentityError;

/// A user session.
///
/// # Examples
///
/// ```
/// use secure_identity::session::InMemorySessionManager;
///
/// let mgr = InMemorySessionManager::new();
/// ```
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// Cryptographically random session ID (128 bits, hex-encoded).
    pub id: String,
    /// The actor this session belongs to.
    pub actor_id: ActorId,
    /// The tenant this session belongs to, if applicable.
    pub tenant_id: Option<TenantId>,
    /// The roles assigned to this actor for this session.
    pub roles: Vec<String>,
    /// When the session was created.
    pub created_at: OffsetDateTime,
    /// When the session expires.
    pub expires_at: OffsetDateTime,
    /// When the session was last accessed.
    pub last_accessed: OffsetDateTime,
}

/// A trait for managing sessions.
///
/// # Examples
///
/// ```
/// use secure_identity::session::InMemorySessionManager;
///
/// // InMemorySessionManager implements SessionManager.
/// let mgr = InMemorySessionManager::new();
/// ```
#[allow(async_fn_in_trait)]
pub trait SessionManager {
    /// Creates a new session for the given identity with the given lifetime in seconds.
    async fn create_session(
        &self,
        identity: &AuthenticatedIdentity,
        lifetime_secs: u64,
    ) -> Result<Session, IdentityError>;

    /// Validates a session by ID, returning it if valid and not expired.
    async fn validate_session(&self, id: &str) -> Result<Session, IdentityError>;

    /// Refreshes a session by ID, extending it by `extra_secs` seconds.
    async fn refresh_session(&self, id: &str, extra_secs: u64) -> Result<Session, IdentityError>;

    /// Revokes a session by ID.
    async fn revoke_session(&self, id: &str) -> Result<(), IdentityError>;
}

fn generate_session_id() -> Result<String, IdentityError> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes)
        .map_err(|_| IdentityError::ProviderUnavailable)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// An in-memory session manager backed by a `tokio::sync::Mutex<HashMap>`.
///
/// # Examples
///
/// ```
/// use secure_identity::session::InMemorySessionManager;
///
/// let mgr = InMemorySessionManager::new();
/// ```
pub struct InMemorySessionManager {
    sessions: Mutex<HashMap<String, Session>>,
}

impl InMemorySessionManager {
    /// Creates a new empty [`InMemorySessionManager`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager for InMemorySessionManager {
    async fn create_session(
        &self,
        identity: &AuthenticatedIdentity,
        lifetime_secs: u64,
    ) -> Result<Session, IdentityError> {
        let id = generate_session_id()?;
        let now = OffsetDateTime::now_utc();
        #[allow(clippy::cast_possible_truncation)]
        let expires_at = now + time::Duration::seconds(lifetime_secs as i64);
        let session = Session {
            id: id.clone(),
            actor_id: identity.actor_id.clone(),
            tenant_id: identity.tenant_id.clone(),
            roles: identity.roles.clone(),
            created_at: now,
            expires_at,
            last_accessed: now,
        };
        self.sessions.lock().await.insert(id, session.clone());
        Ok(session)
    }

    async fn validate_session(&self, id: &str) -> Result<Session, IdentityError> {
        let now = OffsetDateTime::now_utc();
        let mut guard = self.sessions.lock().await;
        let session = guard
            .get(id)
            .cloned()
            .ok_or(IdentityError::SessionExpired)?;
        if now > session.expires_at {
            guard.remove(id);
            return Err(IdentityError::SessionExpired);
        }
        let mut session = session;
        session.last_accessed = now;
        guard.insert(id.to_owned(), session.clone());
        Ok(session)
    }

    async fn refresh_session(&self, id: &str, extra_secs: u64) -> Result<Session, IdentityError> {
        let now = OffsetDateTime::now_utc();
        let mut guard = self.sessions.lock().await;
        let session = guard.get_mut(id).ok_or(IdentityError::SessionExpired)?;
        if now > session.expires_at {
            return Err(IdentityError::SessionExpired);
        }
        #[allow(clippy::cast_possible_truncation)]
        let extra = time::Duration::seconds(extra_secs as i64);
        session.expires_at += extra;
        session.last_accessed = now;
        Ok(session.clone())
    }

    async fn revoke_session(&self, id: &str) -> Result<(), IdentityError> {
        self.sessions.lock().await.remove(id);
        Ok(())
    }
}

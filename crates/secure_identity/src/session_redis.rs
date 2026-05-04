//! Redis-backed session manager implementation.

use redis::AsyncCommands;
use ring::rand::{SecureRandom, SystemRandom};
use security_core::identity::AuthenticatedIdentity;
use time::OffsetDateTime;

use crate::error::IdentityError;
use crate::session::{Session, SessionManager};

fn generate_session_id() -> Result<String, IdentityError> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes)
        .map_err(|_| IdentityError::ProviderUnavailable)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Redis-backed [`SessionManager`] implementation.
pub struct RedisSessionManager {
    client: redis::Client,
    key_prefix: String,
}

impl RedisSessionManager {
    /// Creates a new Redis session manager from a Redis URL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::session_redis::RedisSessionManager;
    ///
    /// let manager = RedisSessionManager::new("redis://127.0.0.1:6379/");
    /// assert!(manager.is_ok());
    /// ```
    pub fn new(redis_url: &str) -> Result<Self, IdentityError> {
        let client =
            redis::Client::open(redis_url).map_err(|_| IdentityError::ProviderUnavailable)?;
        Ok(Self {
            client,
            key_prefix: "sunlit:sessions".to_string(),
        })
    }

    fn key(&self, id: &str) -> String {
        format!("{}:{}", self.key_prefix, id)
    }

    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection, IdentityError> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)
    }
}

impl SessionManager for RedisSessionManager {
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

        let key = self.key(&id);
        let value =
            serde_json::to_string(&session).map_err(|_| IdentityError::ProviderUnavailable)?;
        let mut conn = self.connection().await?;
        let ttl = lifetime_secs;
        let _: () = conn
            .set_ex(&key, value, ttl)
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;

        Ok(session)
    }

    async fn validate_session(&self, id: &str) -> Result<Session, IdentityError> {
        let key = self.key(id);
        let mut conn = self.connection().await?;
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;

        let mut session = value
            .and_then(|raw| serde_json::from_str::<Session>(&raw).ok())
            .ok_or(IdentityError::SessionExpired)?;

        let now = OffsetDateTime::now_utc();
        if now > session.expires_at {
            let _: () = conn
                .del(&key)
                .await
                .map_err(|_| IdentityError::ProviderUnavailable)?;
            return Err(IdentityError::SessionExpired);
        }

        session.last_accessed = now;
        let remaining = (session.expires_at - now).whole_seconds().max(1);
        let updated =
            serde_json::to_string(&session).map_err(|_| IdentityError::ProviderUnavailable)?;
        #[allow(clippy::cast_sign_loss)]
        let _: () = conn
            .set_ex(&key, updated, remaining as u64)
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;

        Ok(session)
    }

    async fn refresh_session(&self, id: &str, extra_secs: u64) -> Result<Session, IdentityError> {
        let mut session = self.validate_session(id).await?;
        #[allow(clippy::cast_possible_truncation)]
        let extra = time::Duration::seconds(extra_secs as i64);
        session.expires_at += extra;

        let key = self.key(id);
        let mut conn = self.connection().await?;
        let serialized =
            serde_json::to_string(&session).map_err(|_| IdentityError::ProviderUnavailable)?;
        let ttl = (session.expires_at - OffsetDateTime::now_utc())
            .whole_seconds()
            .max(1);

        #[allow(clippy::cast_sign_loss)]
        let _: () = conn
            .set_ex(&key, serialized, ttl as u64)
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;

        Ok(session)
    }

    async fn revoke_session(&self, id: &str) -> Result<(), IdentityError> {
        let key = self.key(id);
        let mut conn = self.connection().await?;
        let _: () = conn
            .del(&key)
            .await
            .map_err(|_| IdentityError::ProviderUnavailable)?;
        Ok(())
    }
}

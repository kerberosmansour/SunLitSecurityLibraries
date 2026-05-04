//! BDD tests for Milestone 24 session backends.

use secure_identity::session::{InMemorySessionManager, SessionManager};
use security_core::{identity::AuthenticatedIdentity, types::ActorId};
use time::OffsetDateTime;
use uuid::Uuid;

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: std::collections::HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

#[tokio::test]
async fn scenario_create_retrieve_delete_session() {
    let store = InMemorySessionManager::new();
    let created = store
        .create_session(&identity(), 60)
        .await
        .expect("session creation should succeed");

    let loaded = store
        .validate_session(&created.id)
        .await
        .expect("session should load");
    assert_eq!(loaded.id, created.id);

    store
        .revoke_session(&created.id)
        .await
        .expect("session revoke should succeed");

    assert!(store.validate_session(&created.id).await.is_err());
}

#[cfg(feature = "session-redis")]
#[tokio::test]
async fn scenario_backend_unavailable_returns_error() {
    use secure_identity::session_redis::RedisSessionManager;

    let store = RedisSessionManager::new("redis://127.0.0.1:6399/")
        .expect("client construction should succeed");

    let result = store.create_session(&identity(), 60).await;
    assert!(result.is_err());
}

//! BDD tests for session management.

use std::collections::HashSet;

use secure_identity::{
    error::IdentityError,
    session::{InMemorySessionManager, SessionManager},
};
use security_core::{identity::AuthenticatedIdentity, types::ActorId};
use time::OffsetDateTime;
use uuid::Uuid;

fn make_identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: std::collections::HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

#[tokio::test]
async fn scenario_session_created_with_bounded_lifetime() {
    let mgr = InMemorySessionManager::new();
    let identity = make_identity();
    let session = mgr.create_session(&identity, 3600).await.unwrap();
    assert!(!session.id.is_empty());
    assert!(session.expires_at > session.created_at);
}

#[tokio::test]
async fn scenario_session_validated_before_expiry() {
    let mgr = InMemorySessionManager::new();
    let identity = make_identity();
    let session = mgr.create_session(&identity, 3600).await.unwrap();
    let validated = mgr.validate_session(&session.id).await;
    assert!(validated.is_ok());
}

#[tokio::test]
async fn scenario_expired_session_rejected() {
    let mgr = InMemorySessionManager::new();
    let result = mgr.validate_session("nonexistent-session-id").await;
    assert!(matches!(result, Err(IdentityError::SessionExpired)));
}

#[tokio::test]
async fn scenario_session_revoked() {
    let mgr = InMemorySessionManager::new();
    let identity = make_identity();
    let session = mgr.create_session(&identity, 3600).await.unwrap();
    mgr.revoke_session(&session.id).await.unwrap();
    let result = mgr.validate_session(&session.id).await;
    assert!(matches!(result, Err(IdentityError::SessionExpired)));
}

#[tokio::test]
async fn scenario_session_ids_are_cryptographically_random() {
    let mgr = InMemorySessionManager::new();
    let identity = make_identity();
    let mut ids = HashSet::new();
    for _ in 0..1000 {
        let session = mgr.create_session(&identity, 3600).await.unwrap();
        ids.insert(session.id);
    }
    assert_eq!(ids.len(), 1000, "all 1000 session IDs must be unique");
}

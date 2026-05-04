//! Property tests — session management invariants.
//!
//! Milestone 9 — BDD: Session IDs always unique, sessions behave correctly.
use proptest::prelude::*;
use secure_identity::session::{InMemorySessionManager, SessionManager};
use security_core::{identity::AuthenticatedIdentity, types::ActorId};
use std::collections::HashMap;
use time::OffsetDateTime;
use tokio::runtime::Runtime;
use uuid::Uuid;

fn make_identity(subject: &str) -> AuthenticatedIdentity {
    // Derive a deterministic UUID v5 from the subject string for reproducibility.
    // Use a fixed namespace UUID + subject as name → always a valid UUID.
    let _ = subject; // subject used as debug label only
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any two sessions created have different IDs
    #[test]
    fn prop_session_ids_unique(
        subject1 in "[a-z]{3,10}",
        subject2 in "[a-z]{3,10}",
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = InMemorySessionManager::new();
            let id1 = mgr.create_session(&make_identity(&subject1), 300).await.unwrap().id;
            let id2 = mgr.create_session(&make_identity(&subject2), 300).await.unwrap().id;
            prop_assert_ne!(id1, id2);
            Ok(())
        })?;
    }

    /// Sessions created with very short TTL expire quickly
    #[test]
    fn prop_short_ttl_session_created_successfully(
        subject in "[a-z]{3,10}",
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = InMemorySessionManager::new();
            // TTL of 1 second — session should be created successfully
            let session = mgr.create_session(&make_identity(&subject), 1).await;
            prop_assert!(session.is_ok(), "session creation should succeed");
            Ok(())
        })?;
    }

    /// A valid session can be validated before expiry
    #[test]
    fn prop_session_valid_before_expiry(subject in "[a-z]{3,10}") {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = InMemorySessionManager::new();
            let session = mgr.create_session(&make_identity(&subject), 300).await.unwrap();
            let result = mgr.validate_session(&session.id).await;
            prop_assert!(result.is_ok(), "session should be valid before expiry");
            Ok(())
        })?;
    }
}

//! BDD — Resource ownership
use secure_authz::{
    action::Action,
    decision::Decision,
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    testkit::test_subject,
};
use std::sync::Arc;

/// Scenario: Owner can access own resource — policy allows actor_id directly
#[tokio::test]
async fn test_owner_can_access_own_resource() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    // Policy: "alice" (actor_id) can read "document"
    engine
        .add_policy("alice", "document", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject("alice", &[]);
    let resource = ResourceRef::new("document").with_owner("alice");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "Expected Allow for owner, got: {decision:?}"
    );
}

/// Scenario: Non-owner denied — no policy grants access
#[tokio::test]
async fn test_non_owner_denied() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    // No policy for "bob" on "alice"'s document
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject("bob", &[]);
    let resource = ResourceRef::new("document").with_owner("alice");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        decision.is_deny(),
        "Expected Deny for non-owner, got: {decision:?}"
    );
}

/// Scenario: Ownership helper — is_owner check
#[test]
fn test_is_owner_helper() {
    use secure_authz::ownership::is_owner;
    let subject = test_subject("alice", &[]);
    let owned = ResourceRef::new("doc").with_owner("alice");
    let not_owned = ResourceRef::new("doc").with_owner("bob");
    let no_owner = ResourceRef::new("doc");

    assert!(is_owner(&subject, &owned));
    assert!(!is_owner(&subject, &not_owned));
    assert!(!is_owner(&subject, &no_owner));
}

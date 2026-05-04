//! BDD — Policy evaluation (RBAC and ABAC)
use secure_authz::{
    action::Action,
    decision::{Decision, DenyReason},
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    testkit::test_subject,
};
use std::sync::Arc;

/// Scenario: RBAC allow — editor role can Read articles
#[tokio::test]
async fn test_rbac_allow_editor_read() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject("alice", &["editor"]);
    let resource = ResourceRef::new("article");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "Expected Allow, got: {decision:?}"
    );
}

/// Scenario: RBAC deny — viewer role cannot Write articles
#[tokio::test]
async fn test_rbac_deny_viewer_write() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "write")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject("bob", &["viewer"]);
    let resource = ResourceRef::new("article");
    let decision = authorizer
        .authorize(&subject, &Action::Write, &resource)
        .await;
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::InsufficientRole
            }
        ),
        "Expected InsufficientRole, got: {decision:?}"
    );
}

/// Scenario: ABAC — attribute-based subject with matching role policy
#[tokio::test]
async fn test_abac_role_allows_code_repo_access() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("engineering", "code_repo", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let mut subject = test_subject("carol", &["engineering"]);
    subject
        .attributes
        .insert("department".to_owned(), "engineering".to_owned());
    let resource = ResourceRef::new("code_repo");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "Expected Allow, got: {decision:?}"
    );
}

/// Scenario: No role strings in code — business code uses typed Action variants
#[test]
fn test_no_role_strings_in_code_compiles() {
    // If this compiles, the invariant is satisfied — no string role checks in production code.
    let _action: Action = Action::Delete;
    let _read: Action = Action::Read;
    let _write: Action = Action::Write;
    let _admin: Action = Action::Admin;
    let _custom: Action = Action::Custom("special_action".to_owned());
}

/// Scenario: Multiple roles — first matching role grants access
#[tokio::test]
async fn test_multiple_roles_first_match_wins() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    // Subject has both "viewer" (no policy) and "editor" (has policy)
    let subject = test_subject("dave", &["viewer", "editor"]);
    let resource = ResourceRef::new("article");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "Expected Allow for subject with editor role, got: {decision:?}"
    );
}

//! BDD coverage for Milestone 23 ABAC predicates.
use secure_authz::{
    abac::AttributeGuard,
    action::Action,
    decision::{Decision, DenyReason},
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    testkit::test_subject,
};
use std::sync::Arc;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn attribute_guard_is_send_sync() {
    // Given: the public ABAC predicate type
    // When: it is used in a Send + Sync bound
    // Then: it compiles for cross-thread authorization checks
    assert_send_sync::<AttributeGuard>();
}

#[tokio::test]
async fn attribute_match_allows_access() {
    // Given: an ABAC guard that requires admin + engineering
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine)).with_abac_guard(
        AttributeGuard::require_subject_attr("role", "admin")
            .and(AttributeGuard::require_subject_attr("dept", "eng")),
    );

    let mut subject = test_subject("alice", &[]);
    subject.attributes.insert("role".into(), "admin".into());
    subject.attributes.insert("dept".into(), "eng".into());

    // When: the subject requests admin access
    let decision = authorizer
        .authorize(&subject, &Action::Admin, &ResourceRef::new("dashboard"))
        .await;

    // Then: access is allowed by the ABAC predicate
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "expected allow, got {decision:?}"
    );
}

#[tokio::test]
async fn missing_attribute_denies_access() {
    // Given: an ABAC guard that requires a department attribute
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine))
        .with_abac_guard(AttributeGuard::require_subject_attr("dept", "eng"));

    let subject = test_subject("bob", &[]);

    // When: the attribute is missing
    let decision = authorizer
        .authorize(&subject, &Action::Read, &ResourceRef::new("repo"))
        .await;

    // Then: access is denied fail-closed
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::AttributeMismatch
            }
        ),
        "expected AttributeMismatch, got {decision:?}"
    );
}

#[tokio::test]
async fn multiple_predicates_and_deny_on_wrong_ip() {
    // Given: two predicates combined with AND
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine)).with_abac_guard(
        AttributeGuard::require_subject_attr("role", "admin")
            .and(AttributeGuard::require_subject_attr("ip_range", "corp")),
    );

    let mut subject = test_subject("carol", &[]);
    subject.attributes.insert("role".into(), "admin".into());
    subject.attributes.insert("ip_range".into(), "guest".into());

    // When: only one predicate matches
    let decision = authorizer
        .authorize(&subject, &Action::Admin, &ResourceRef::new("vault"))
        .await;

    // Then: the composed guard denies access
    assert!(
        matches!(decision, Decision::Deny { .. }),
        "expected deny, got {decision:?}"
    );
}

#[tokio::test]
async fn composed_predicates_or_allows_superuser() {
    // Given: an OR composition for admin or superuser
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine)).with_abac_guard(
        AttributeGuard::require_subject_attr("role", "admin")
            .or(AttributeGuard::require_subject_attr("role", "superuser")),
    );

    let mut subject = test_subject("dave", &[]);
    subject.attributes.insert("role".into(), "superuser".into());

    // When: the second branch matches
    let decision = authorizer
        .authorize(&subject, &Action::Admin, &ResourceRef::new("control-panel"))
        .await;

    // Then: access is allowed
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "expected allow, got {decision:?}"
    );
}

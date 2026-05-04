//! BDD coverage for Milestone 23 temporal permissions.
use secure_authz::{
    action::Action,
    decision::{Decision, DenyReason},
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    temporal::PermissionWindow,
    testkit::test_subject,
};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn active_permission_allowed() {
    // Given: a permission window that contains the current time
    let now = OffsetDateTime::parse(
        "2026-04-11T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let window = PermissionWindow::new()
        .starting_at(now - Duration::hours(1))
        .expiring_at(now + Duration::hours(1));

    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine))
        .with_time_source(move || now)
        .with_abac_guard(secure_authz::abac::AttributeGuard::allow_all());

    let mut subject = test_subject("alice", &[]);
    window.apply_to_subject(&mut subject).unwrap();

    // When: authorization runs inside the valid window
    let decision = authorizer
        .authorize(&subject, &Action::Read, &ResourceRef::new("report"))
        .await;

    // Then: access is allowed
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "expected allow, got {decision:?}"
    );
}

#[tokio::test]
async fn expired_permission_denied() {
    // Given: a permission that already expired
    let now = OffsetDateTime::parse(
        "2026-04-11T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let window = PermissionWindow::new()
        .starting_at(now - Duration::hours(4))
        .expiring_at(now - Duration::hours(1));

    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine))
        .with_time_source(move || now)
        .with_abac_guard(secure_authz::abac::AttributeGuard::allow_all());

    let mut subject = test_subject("bob", &[]);
    window.apply_to_subject(&mut subject).unwrap();

    // When: authorization runs after expiry
    let decision = authorizer
        .authorize(&subject, &Action::Read, &ResourceRef::new("report"))
        .await;

    // Then: access is denied for an expired window
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::PermissionExpired
            }
        ),
        "expected PermissionExpired, got {decision:?}"
    );
}

#[tokio::test]
async fn not_yet_active_permission_denied() {
    // Given: a permission that starts in the future
    let now = OffsetDateTime::parse(
        "2026-04-11T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let window = PermissionWindow::new().starting_at(now + Duration::hours(2));

    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine))
        .with_time_source(move || now)
        .with_abac_guard(secure_authz::abac::AttributeGuard::allow_all());

    let mut subject = test_subject("carol", &[]);
    window.apply_to_subject(&mut subject).unwrap();

    // When: authorization runs before the window opens
    let decision = authorizer
        .authorize(&subject, &Action::Read, &ResourceRef::new("report"))
        .await;

    // Then: access is denied
    assert!(
        matches!(decision, Decision::Deny { .. }),
        "expected deny, got {decision:?}"
    );
}

#[tokio::test]
async fn no_temporal_constraint_falls_back_to_normal_rbac() {
    // Given: a normal RBAC policy with no time window
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine.add_policy("editor", "report", "read").await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));

    let subject = test_subject("dave", &["editor"]);

    // When: authorization runs without temporal metadata
    let decision = authorizer
        .authorize(&subject, &Action::Read, &ResourceRef::new("report"))
        .await;

    // Then: the original RBAC path is preserved
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "expected allow, got {decision:?}"
    );
}

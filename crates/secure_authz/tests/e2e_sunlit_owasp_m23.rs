//! End-to-end runtime validation for Milestone 23.
use secure_authz::{
    abac::AttributeGuard,
    action::Action,
    cache::{CacheKey, DecisionCache},
    decision::Decision,
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    temporal::PermissionWindow,
    testkit::test_subject_with_tenant,
};
use std::{sync::Arc, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn test_abac_attribute_evaluation() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine)).with_abac_guard(
        AttributeGuard::require_subject_attr("department", "engineering"),
    );

    let mut subject = test_subject_with_tenant("alice", "tenant-a", &[]);
    subject
        .attributes
        .insert("department".into(), "engineering".into());

    let decision = authorizer
        .authorize(
            &subject,
            &Action::Read,
            &ResourceRef::new("repo").with_tenant("tenant-a"),
        )
        .await;

    assert!(
        matches!(decision, Decision::Allow { .. }),
        "expected allow, got {decision:?}"
    );
}

#[tokio::test]
async fn test_temporal_permission_expiry() {
    let now = OffsetDateTime::parse(
        "2026-04-11T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let window = PermissionWindow::new()
        .starting_at(now - Duration::hours(2))
        .expiring_at(now - Duration::minutes(5));

    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine))
        .with_time_source(move || now)
        .with_abac_guard(AttributeGuard::allow_all());

    let mut subject = test_subject_with_tenant("bob", "tenant-a", &[]);
    window.apply_to_subject(&mut subject).unwrap();

    let decision = authorizer
        .authorize(
            &subject,
            &Action::Read,
            &ResourceRef::new("report").with_tenant("tenant-a"),
        )
        .await;

    assert!(decision.is_deny(), "expected deny, got {decision:?}");
}

#[tokio::test]
async fn test_tenant_isolation_in_cache() {
    let cache = DecisionCache::new(16, StdDuration::from_secs(30));
    let key_a = CacheKey::for_request(
        &test_subject_with_tenant("alice", "tenant-a", &["editor"]),
        &Action::Read,
        &ResourceRef::new("doc")
            .with_id("123")
            .with_tenant("tenant-a"),
        1,
    );
    let key_b = CacheKey::for_request(
        &test_subject_with_tenant("alice", "tenant-b", &["editor"]),
        &Action::Read,
        &ResourceRef::new("doc")
            .with_id("123")
            .with_tenant("tenant-b"),
        1,
    );

    cache.insert(
        key_a,
        Decision::Allow {
            obligations: vec![],
        },
    );

    assert!(
        cache.get(&key_b).is_none(),
        "tenant-b must not receive tenant-a cache entry"
    );
}

#[tokio::test]
async fn test_bulk_authorization_correctness() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine.add_policy("editor", "report", "read").await.unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));

    let requests = vec![
        (
            test_subject_with_tenant("alice", "tenant-a", &["editor"]),
            Action::Read,
            ResourceRef::new("report").with_tenant("tenant-a"),
        ),
        (
            test_subject_with_tenant("bob", "tenant-a", &["viewer"]),
            Action::Read,
            ResourceRef::new("report").with_tenant("tenant-a"),
        ),
    ];

    let decisions = authorizer.authorize_bulk(&requests).await;

    assert_eq!(decisions.len(), 2);
    assert!(decisions[0].is_allow(), "expected first request to allow");
    assert!(decisions[1].is_deny(), "expected second request to deny");
}

#[tokio::test]
async fn test_existing_rbac_still_works() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));

    let subject = test_subject_with_tenant("erin", "tenant-a", &["editor"]);
    let decision = authorizer
        .authorize(
            &subject,
            &Action::Read,
            &ResourceRef::new("article").with_tenant("tenant-a"),
        )
        .await;

    assert!(
        matches!(decision, Decision::Allow { .. }),
        "expected RBAC allow, got {decision:?}"
    );
}

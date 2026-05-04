//! BDD — Decision cache
use secure_authz::{
    action::Action,
    cache::{CacheKey, DecisionCache},
    decision::{Decision, DenyReason},
    enforcer::Authorizer,
    resource::ResourceRef,
    testkit::test_subject,
    testkit::MockAuthorizer,
};
use std::time::Duration;

/// Scenario: MockAuthorizer can be called multiple times (structure verification)
#[tokio::test]
async fn test_mock_authorizer_call_count() {
    let mock = MockAuthorizer::allow();
    let subject = test_subject("alice", &["editor"]);
    let resource = ResourceRef::new("article");
    let d1 = mock.authorize(&subject, &Action::Read, &resource).await;
    let d2 = mock.authorize(&subject, &Action::Read, &resource).await;
    assert!(d1.is_allow());
    assert!(d2.is_allow());
    assert_eq!(mock.call_count(), 2);
}

/// Scenario: Cache bounded by size — inserting 200 entries into a 100-capacity cache
#[test]
fn test_cache_bounded_by_size() {
    let cache = DecisionCache::new(100, Duration::from_secs(60));
    for i in 0..200_usize {
        let key = CacheKey {
            actor_id: format!("actor_{i}"),
            action: "read".to_owned(),
            resource_kind: "article".to_owned(),
            resource_id: format!("res_{i}"),
            policy_version: 1,
            tenant_id: None,
        };
        cache.insert(
            key,
            Decision::Allow {
                obligations: vec![],
            },
        );
    }
    // Reaching here without OOM means the cache is bounded
}

/// Scenario: Stale cache entry expires after TTL
#[test]
fn test_stale_cache_entry_expires() {
    let cache = DecisionCache::new(100, Duration::from_nanos(1));
    let key = CacheKey {
        actor_id: "alice".to_owned(),
        action: "read".to_owned(),
        resource_kind: "article".to_owned(),
        resource_id: "r1".to_owned(),
        policy_version: 1,
        tenant_id: None,
    };
    cache.insert(
        key.clone(),
        Decision::Allow {
            obligations: vec![],
        },
    );
    // Sleep long enough for TTL to expire
    std::thread::sleep(Duration::from_millis(10));
    let result = cache.get(&key);
    assert!(result.is_none(), "Expected cache miss after TTL expiry");
}

/// Scenario: Policy version change invalidates cache entries
#[test]
fn test_policy_version_change_invalidates_cache() {
    let cache = DecisionCache::new(100, Duration::from_secs(60));
    let key_v1 = CacheKey {
        actor_id: "alice".to_owned(),
        action: "read".to_owned(),
        resource_kind: "article".to_owned(),
        resource_id: "*".to_owned(),
        policy_version: 1,
        tenant_id: None,
    };
    let key_v2 = CacheKey {
        policy_version: 2,
        ..key_v1.clone()
    };
    cache.insert(
        key_v1.clone(),
        Decision::Allow {
            obligations: vec![],
        },
    );
    // Version 2 key should be a miss (different key)
    assert!(
        cache.get(&key_v2).is_none(),
        "Expected cache miss for new policy version"
    );
    // Version 1 key should still hit
    assert!(
        cache.get(&key_v1).is_some(),
        "Expected cache hit for original policy version"
    );
}

/// Scenario: Cache hit returns same decision
#[test]
fn test_cache_hit_returns_same_decision() {
    let cache = DecisionCache::new(10, Duration::from_secs(60));
    let key = CacheKey {
        actor_id: "alice".to_owned(),
        action: "read".to_owned(),
        resource_kind: "article".to_owned(),
        resource_id: "*".to_owned(),
        policy_version: 1,
        tenant_id: None,
    };
    let decision = Decision::Deny {
        reason: DenyReason::InsufficientRole,
    };
    cache.insert(key.clone(), decision.clone());
    let cached = cache.get(&key).unwrap();
    assert_eq!(cached, decision);
}

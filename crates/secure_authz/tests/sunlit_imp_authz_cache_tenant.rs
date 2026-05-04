//! BDD tests for M15: Tenant-scoped cache and obligation enforcement.

use secure_authz::cache::{CacheKey, DecisionCache};
use secure_authz::decision::{Decision, DenyReason};
use std::time::Duration;

// ---------- Feature: Tenant-scoped cache ----------

#[test]
fn same_actor_different_tenants_get_separate_cache_entries() {
    // Given: actor A in tenant X is allowed, actor A in tenant Y is denied
    let cache = DecisionCache::new(64, Duration::from_secs(60));

    let key_tenant_x = CacheKey {
        actor_id: "actor-a".into(),
        action: "read".into(),
        resource_kind: "article".into(),
        resource_id: "42".into(),
        policy_version: 1,
        tenant_id: Some("tenant-x".into()),
    };

    let key_tenant_y = CacheKey {
        actor_id: "actor-a".into(),
        action: "read".into(),
        resource_kind: "article".into(),
        resource_id: "42".into(),
        policy_version: 1,
        tenant_id: Some("tenant-y".into()),
    };

    cache.insert(
        key_tenant_x.clone(),
        Decision::Allow {
            obligations: vec![],
        },
    );
    cache.insert(
        key_tenant_y.clone(),
        Decision::Deny {
            reason: DenyReason::InsufficientRole,
        },
    );

    // When: check cache for both
    let result_x = cache.get(&key_tenant_x);
    let result_y = cache.get(&key_tenant_y);

    // Then: different decisions returned
    assert!(result_x.unwrap().is_allow());
    assert!(result_y.unwrap().is_deny());
}

#[test]
fn single_tenant_cache_still_works() {
    // Given: no tenant_id on subject or resource
    let cache = DecisionCache::new(64, Duration::from_secs(60));

    let key = CacheKey {
        actor_id: "actor-b".into(),
        action: "write".into(),
        resource_kind: "document".into(),
        resource_id: "99".into(),
        policy_version: 1,
        tenant_id: None,
    };

    cache.insert(
        key.clone(),
        Decision::Allow {
            obligations: vec![],
        },
    );

    // When: authorization check
    let result = cache.get(&key);

    // Then: cache works as before
    assert!(result.unwrap().is_allow());
}

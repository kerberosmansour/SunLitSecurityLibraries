//! Bounded LRU decision cache with TTL and policy-version keying.
use crate::decision::Decision;
use crate::{action::Action, resource::ResourceRef, subject::Subject};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A cache key that includes the policy version and tenant to allow version-based invalidation
/// and tenant isolation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The actor performing the request.
    pub actor_id: String,
    /// The action being checked.
    pub action: String,
    /// The kind of resource.
    pub resource_kind: String,
    /// The resource identifier.
    pub resource_id: String,
    /// The policy version at the time of evaluation.
    pub policy_version: u64,
    /// The tenant scope for this cache entry (prevents cross-tenant cache poisoning).
    pub tenant_id: Option<String>,
}

impl CacheKey {
    /// Constructs the public, low-level request key.
    ///
    /// This key does not bind roles. `DefaultAuthorizer` adds an exact role
    /// binding internally and isolates its entries from low-level `get`/`insert`.
    /// Applications managing decisions directly must invalidate entries when
    /// authorization context changes.
    #[must_use]
    pub fn for_request(
        subject: &Subject,
        action: &Action,
        resource: &ResourceRef,
        policy_version: u64,
    ) -> Self {
        Self {
            actor_id: subject.actor_id.clone(),
            action: action.to_string(),
            resource_kind: resource.kind.clone(),
            resource_id: resource
                .resource_id
                .clone()
                .unwrap_or_else(|| "*".to_string()),
            policy_version,
            tenant_id: subject.tenant_id.clone(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum CacheScope {
    Manual,
    Roles(Vec<String>),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ScopedKey {
    request: CacheKey,
    scope: CacheScope,
}

struct CachedEntry {
    decision: Decision,
    cached_at: Instant,
}

/// Bounded LRU decision cache with TTL and policy-version-keyed invalidation.
///
/// Entries older than `ttl` are treated as cache misses. The cache is bounded by `max_size`.
pub struct DecisionCache {
    inner: Mutex<LruCache<ScopedKey, CachedEntry>>,
    ttl: Duration,
}

impl DecisionCache {
    /// Creates a new cache with the given capacity and TTL.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::cache::DecisionCache;
    /// use std::time::Duration;
    ///
    /// let cache = DecisionCache::new(1024, Duration::from_secs(300));
    /// ```
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        let capacity = NonZeroUsize::new(max_size).unwrap_or_else(|| NonZeroUsize::new(1).unwrap());
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
            ttl,
        }
    }

    /// Returns the cached decision if it exists and has not expired.
    pub fn get(&self, key: &CacheKey) -> Option<Decision> {
        self.get_scoped(&ScopedKey {
            request: key.clone(),
            scope: CacheScope::Manual,
        })
    }

    pub(crate) fn get_for_request(&self, key: &CacheKey, roles: &[String]) -> Option<Decision> {
        self.get_scoped(&ScopedKey {
            request: key.clone(),
            scope: CacheScope::Roles(roles.to_vec()),
        })
    }

    fn get_scoped(&self, key: &ScopedKey) -> Option<Decision> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.get(key) {
            if entry.cached_at.elapsed() < self.ttl {
                return Some(entry.decision.clone());
            }
        }
        None
    }

    /// Stores a decision in the cache, evicting the oldest entry if at capacity.
    pub fn insert(&self, key: CacheKey, decision: Decision) {
        self.insert_scoped(
            ScopedKey {
                request: key,
                scope: CacheScope::Manual,
            },
            decision,
        );
    }

    pub(crate) fn insert_for_request(&self, key: CacheKey, roles: &[String], decision: Decision) {
        self.insert_scoped(
            ScopedKey {
                request: key,
                scope: CacheScope::Roles(roles.to_vec()),
            },
            decision,
        );
    }

    fn insert_scoped(&self, key: ScopedKey, decision: Decision) {
        let mut inner = self.inner.lock().unwrap();
        inner.put(
            key,
            CachedEntry {
                decision,
                cached_at: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod role_binding_tests {
    use super::*;

    fn key() -> CacheKey {
        CacheKey::for_request(
            &crate::testkit::test_subject("alice", &["owner"]),
            &Action::Read,
            &ResourceRef::new("document"),
            1,
        )
    }

    fn allow() -> Decision {
        Decision::Allow {
            obligations: vec![],
        }
    }

    #[test]
    fn request_entries_hit_only_for_exact_ordered_roles() {
        let cache = DecisionCache::new(2, Duration::from_secs(60));
        let roles = vec!["owner".to_owned(), "reader".to_owned()];
        cache.insert_for_request(key(), &roles, allow());
        assert_eq!(cache.get_for_request(&key(), &roles), Some(allow()));
        assert!(cache
            .get_for_request(&key(), &["reader".into(), "owner".into()])
            .is_none());
        assert!(cache.get_for_request(&key(), &[]).is_none());
        assert!(cache.get(&key()).is_none());
    }

    #[test]
    fn request_entries_share_capacity_and_expire() {
        let roles = vec!["owner".to_owned()];
        let cache = DecisionCache::new(1, Duration::from_secs(60));
        cache.insert_for_request(key(), &roles, allow());
        cache.insert(key(), allow());
        assert!(cache.get_for_request(&key(), &roles).is_none());
        assert_eq!(cache.get(&key()), Some(allow()));
        let expired = DecisionCache::new(1, Duration::ZERO);
        expired.insert_for_request(key(), &roles, allow());
        assert!(expired.get_for_request(&key(), &roles).is_none());
    }
}

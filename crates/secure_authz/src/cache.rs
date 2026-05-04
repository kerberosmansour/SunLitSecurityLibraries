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
    /// Constructs a cache key from an authorization request tuple.
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

struct CachedEntry {
    decision: Decision,
    cached_at: Instant,
}

/// Bounded LRU decision cache with TTL and policy-version-keyed invalidation.
///
/// Entries older than `ttl` are treated as cache misses. The cache is bounded by `max_size`.
pub struct DecisionCache {
    inner: Mutex<LruCache<CacheKey, CachedEntry>>,
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

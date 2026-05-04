//! Authorizer trait and DefaultAuthorizer.
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

use crate::abac::AttributeGuard;
use crate::action::Action;
use crate::cache::DecisionCache;
use crate::decision::{Decision, DenyReason};
use crate::decision_log::log_decision;
use crate::ownership::is_same_tenant;
use crate::policy::PolicyEngine;
use crate::resource::ResourceRef;
use crate::subject::Subject;
use crate::temporal::PermissionWindow;

/// The authorization interface.
///
/// All authorization checks must go through this trait.
/// Deny by default: any error, missing context, or no matching policy returns [`Decision::Deny`].
///
/// # Examples
///
/// ```
/// use secure_authz::testkit::MockAuthorizer;
/// use secure_authz::enforcer::Authorizer;
///
/// let authz = MockAuthorizer::allow();
/// ```
pub trait Authorizer: Send + Sync {
    /// Authorizes `subject` to perform `action` on `resource`.
    fn authorize<'a>(
        &'a self,
        subject: &'a Subject,
        action: &'a Action,
        resource: &'a ResourceRef,
    ) -> Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>>;
}

/// Default authorizer backed by a [`PolicyEngine`] with caching and decision logging.
///
/// # Examples
///
/// See [`crate::testkit::MockAuthorizer`] for testing usage.
pub struct DefaultAuthorizer<P: PolicyEngine> {
    engine: Arc<P>,
    cache: Arc<DecisionCache>,
    abac_guard: Option<AttributeGuard>,
    time_source: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
}

impl<P: PolicyEngine + 'static> DefaultAuthorizer<P> {
    /// Creates a new authorizer with the given policy engine.
    ///
    /// Uses a default cache of 1024 entries with a 5-minute TTL.
    pub fn new(engine: Arc<P>) -> Self {
        Self {
            engine,
            cache: Arc::new(DecisionCache::new(1024, Duration::from_secs(300))),
            abac_guard: None,
            time_source: Arc::new(OffsetDateTime::now_utc),
        }
    }

    /// Creates an authorizer with a custom cache.
    pub fn with_cache(engine: Arc<P>, cache: Arc<DecisionCache>) -> Self {
        Self {
            engine,
            cache,
            abac_guard: None,
            time_source: Arc::new(OffsetDateTime::now_utc),
        }
    }

    /// Adds an ABAC guard used for request-level authorization.
    #[must_use]
    pub fn with_abac_guard(mut self, guard: AttributeGuard) -> Self {
        self.abac_guard = Some(guard);
        self
    }

    /// Overrides the clock source used for temporal permission checks.
    #[must_use]
    pub fn with_time_source<F>(mut self, time_source: F) -> Self
    where
        F: Fn() -> OffsetDateTime + Send + Sync + 'static,
    {
        self.time_source = Arc::new(time_source);
        self
    }

    /// Authorizes a batch of requests and returns one decision per entry.
    pub async fn authorize_bulk(
        &self,
        requests: &[(Subject, Action, ResourceRef)],
    ) -> Vec<Decision> {
        let mut decisions = Vec::with_capacity(requests.len());
        for (subject, action, resource) in requests {
            decisions.push(self.authorize(subject, action, resource).await);
        }
        decisions
    }
}

impl<P: PolicyEngine + 'static> Authorizer for DefaultAuthorizer<P> {
    fn authorize<'a>(
        &'a self,
        subject: &'a Subject,
        action: &'a Action,
        resource: &'a ResourceRef,
    ) -> Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>> {
        // Clone Arc handles so the async block owns them (avoids lifetime issues).
        let engine = self.engine.clone();
        let cache = self.cache.clone();
        let abac_guard = self.abac_guard.clone();
        let time_source = self.time_source.clone();
        // Clone subject/action/resource data for use inside the async block.
        let subject = subject.clone();
        let action = action.clone();
        let resource = resource.clone();

        Box::pin(async move {
            // 1. Validate subject
            if subject.actor_id.is_empty() {
                let decision = Decision::Deny {
                    reason: DenyReason::IncompleteContext,
                };
                log_decision(&subject, &action, &resource, &decision);
                return decision;
            }

            // 2. Validate resource
            if resource.kind.is_empty() {
                let decision = Decision::Deny {
                    reason: DenyReason::MissingResource,
                };
                log_decision(&subject, &action, &resource, &decision);
                return decision;
            }

            // 3. Tenant isolation — cross-tenant is always blocked
            if !is_same_tenant(&subject, &resource) {
                let decision = Decision::Deny {
                    reason: DenyReason::TenantMismatch,
                };
                log_decision(&subject, &action, &resource, &decision);
                return decision;
            }

            // 4. Time-bounded permission checks (subject + resource attributes)
            let now = (time_source)();
            if let Some(temporal_deny) = evaluate_temporal(&subject, &resource, now) {
                let decision = Decision::Deny {
                    reason: temporal_deny,
                };
                log_decision(&subject, &action, &resource, &decision);
                return decision;
            }

            // 5. ABAC predicate checks
            if let Some(guard) = &abac_guard {
                let decision = if guard.check(&subject, &resource, &action) {
                    Decision::Allow {
                        obligations: vec![],
                    }
                } else {
                    Decision::Deny {
                        reason: DenyReason::AttributeMismatch,
                    }
                };
                log_decision(&subject, &action, &resource, &decision);
                return decision;
            }

            let action_str = action.to_string();
            let policy_version = engine.policy_version();

            // 6. Check cache
            let cache_key =
                crate::cache::CacheKey::for_request(&subject, &action, &resource, policy_version);
            if let Some(cached) = cache.get(&cache_key) {
                return cached;
            }

            // 7. Evaluate policy engine (actor_id first, then each role)
            let decision = evaluate_policy(&*engine, &subject, &resource.kind, &action_str).await;

            // 8. Cache and log
            cache.insert(cache_key, decision.clone());
            log_decision(&subject, &action, &resource, &decision);
            decision
        })
    }
}

fn evaluate_temporal(
    subject: &Subject,
    resource: &ResourceRef,
    now: OffsetDateTime,
) -> Option<DenyReason> {
    if let Ok(Some(window)) = PermissionWindow::from_attributes(&subject.attributes) {
        if !window.is_active_at(now) {
            if window.valid_from.is_some_and(|valid_from| now < valid_from) {
                return Some(DenyReason::PermissionNotYetActive);
            }
            return Some(DenyReason::PermissionExpired);
        }
    }

    if let Ok(Some(window)) = PermissionWindow::from_attributes(&resource.attributes) {
        if !window.is_active_at(now) {
            if window.valid_from.is_some_and(|valid_from| now < valid_from) {
                return Some(DenyReason::PermissionNotYetActive);
            }
            return Some(DenyReason::PermissionExpired);
        }
    }

    None
}

/// Evaluates the policy engine for the given subject, resource, and action.
///
/// Tries the actor's ID first, then each assigned role, then determines the best deny reason.
async fn evaluate_policy<P: PolicyEngine>(
    engine: &P,
    subject: &Subject,
    resource: &str,
    action: &str,
) -> Decision {
    match engine.evaluate(&subject.actor_id, resource, action).await {
        Ok(true) => {
            return Decision::Allow {
                obligations: vec![],
            }
        }
        Ok(false) => {}
        Err(_) => {
            return Decision::Deny {
                reason: DenyReason::EngineError,
            }
        }
    }

    for role in &subject.roles {
        match engine.evaluate(role, resource, action).await {
            Ok(true) => {
                return Decision::Allow {
                    obligations: vec![],
                }
            }
            Ok(false) => {}
            Err(_) => {
                return Decision::Deny {
                    reason: DenyReason::EngineError,
                }
            }
        }
    }

    if subject.roles.is_empty() {
        Decision::Deny {
            reason: DenyReason::NoPolicyMatch,
        }
    } else {
        Decision::Deny {
            reason: DenyReason::InsufficientRole,
        }
    }
}

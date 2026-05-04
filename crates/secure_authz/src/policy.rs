//! PolicyEngine — sealed trait abstracting casbin.
use thiserror::Error;

use crate::decision::DenyReason;

/// Errors produced by policy engine operations.
///
/// # Examples
///
/// ```
/// use secure_authz::policy::PolicyError;
///
/// let err = PolicyError::LoadFailed("missing file".into());
/// assert!(err.to_string().contains("missing file"));
/// ```
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Failed to load or initialize the policy engine.
    #[error("policy load failed: {0}")]
    LoadFailed(String),
    /// An error occurred during policy evaluation.
    #[error("policy evaluation error: {0}")]
    EvaluationError(String),
}

impl From<PolicyError> for DenyReason {
    fn from(_: PolicyError) -> Self {
        DenyReason::EngineError
    }
}

mod private {
    /// Sealing marker.
    pub trait Sealed {}
}

/// Sealed trait for the policy evaluation engine.
///
/// Sealed so that only `secure_authz` can provide implementations.
/// Application code depends on [`crate::enforcer::Authorizer`], not this trait.
pub trait PolicyEngine: private::Sealed + Send + Sync {
    /// Evaluates whether `subject` may perform `action` on `resource`.
    fn evaluate(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
    ) -> impl std::future::Future<Output = Result<bool, PolicyError>> + Send;

    /// Evaluates multiple authorization requests in order.
    ///
    /// Implementors can override this for optimized backends; the default
    /// implementation performs sequential evaluations.
    fn evaluate_bulk<'a>(
        &'a self,
        requests: &'a [(&'a str, &'a str, &'a str)],
    ) -> impl std::future::Future<Output = Vec<Result<bool, PolicyError>>> + Send
    where
        Self: Sized,
    {
        async move {
            let mut decisions = Vec::with_capacity(requests.len());
            for (subject, resource, action) in requests {
                decisions.push(self.evaluate(subject, resource, action).await);
            }
            decisions
        }
    }

    /// Returns the current policy version (incremented on each policy mutation).
    fn policy_version(&self) -> u64;
}

// ─── Casbin implementation ─────────────────────────────────────────────────

const RBAC_MODEL_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/rbac_model.conf");
const EMPTY_POLICY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/empty_policy.csv");

use casbin::{CoreApi, MgmtApi};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::Mutex;

/// Default policy engine backed by casbin.
pub struct DefaultPolicyEngine {
    enforcer: Mutex<casbin::Enforcer>,
    version: Arc<AtomicU64>,
}

impl private::Sealed for DefaultPolicyEngine {}

impl DefaultPolicyEngine {
    /// Creates a new engine with an empty (no-policy) state.
    pub async fn new_empty() -> Result<Self, PolicyError> {
        let model = casbin::DefaultModel::from_file(RBAC_MODEL_PATH)
            .await
            .map_err(|e| PolicyError::LoadFailed(e.to_string()))?;
        let adapter = casbin::FileAdapter::new(EMPTY_POLICY_PATH);
        let enforcer = casbin::Enforcer::new(model, adapter)
            .await
            .map_err(|e| PolicyError::LoadFailed(e.to_string()))?;
        Ok(Self {
            enforcer: Mutex::new(enforcer),
            version: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Adds a policy rule: `(subject_or_role, resource, action)`.
    pub async fn add_policy(&self, sub: &str, obj: &str, act: &str) -> Result<(), PolicyError> {
        let mut enforcer = self.enforcer.lock().await;
        enforcer
            .add_policy(vec![sub.to_owned(), obj.to_owned(), act.to_owned()])
            .await
            .map_err(|e| PolicyError::LoadFailed(e.to_string()))?;
        drop(enforcer);
        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Returns all current policies for introspection.
    pub async fn get_policies(&self) -> Vec<Vec<String>> {
        let enforcer = self.enforcer.lock().await;
        let policies = enforcer.get_policy();
        drop(enforcer);
        policies
    }
}

impl PolicyEngine for DefaultPolicyEngine {
    fn evaluate(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
    ) -> impl std::future::Future<Output = Result<bool, PolicyError>> + Send {
        // Clone strings so the future is 'static and Send
        let subject = subject.to_owned();
        let resource = resource.to_owned();
        let action = action.to_owned();
        let enforcer = &self.enforcer;

        async move {
            let guard = enforcer.lock().await;
            let result = guard
                .enforce((subject.as_str(), resource.as_str(), action.as_str()))
                .map_err(|e| PolicyError::EvaluationError(e.to_string()));
            drop(guard);
            result
        }
    }

    fn policy_version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }
}

//! Correlation context and request-scoped metadata.
//!
//! [`CorrelationContext`] threads a request identifier, optional trace identifier, and optional
//! actor identifier through the call stack without relying on thread-local storage. This supports
//! THREAT-T-01 (log tampering) by ensuring all log entries carry the same correlation id.

use crate::types::{ActorId, RequestId, TraceId};

/// A reason code for a security decision (e.g., policy violation, rate limit exceeded).
///
/// Stored as a static string slice to avoid heap allocation on hot paths.
///
/// # Examples
///
/// ```
/// use security_core::context::ReasonCode;
///
/// let code = ReasonCode::new("RATE_LIMIT_EXCEEDED");
/// assert_eq!(code.to_string(), "RATE_LIMIT_EXCEEDED");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReasonCode(pub &'static str);

impl ReasonCode {
    /// Creates a new [`ReasonCode`] from a static string.
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self(code)
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An opaque reference to a secret stored in a secrets manager.
///
/// The inner URI is never exposed via `Display` or `Debug` to prevent accidental logging.
/// Mitigates THREAT-I-02 (credential exposure in logs).
///
/// # Examples
///
/// ```
/// use security_core::context::SecretRef;
///
/// let secret = SecretRef::new("vault://secrets/db-password".to_string());
/// // Debug output is redacted — the URI never leaks.
/// assert_eq!(format!("{:?}", secret), "SecretRef(REDACTED)");
/// // Explicit access is still available when needed.
/// assert_eq!(secret.as_uri(), "vault://secrets/db-password");
/// ```
pub struct SecretRef(String);

impl SecretRef {
    /// Creates a new [`SecretRef`] from a secrets-manager URI.
    #[must_use]
    pub fn new(uri: String) -> Self {
        Self(uri)
    }

    /// Returns the inner URI. Callers must ensure it is not logged or serialized.
    #[must_use]
    pub fn as_uri(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretRef(REDACTED)")
    }
}

/// Carries request-scoped correlation identifiers through the call stack.
///
/// Always attach a [`CorrelationContext`] to every security-relevant operation so that
/// logs, errors, and audit events can be correlated across service boundaries.
///
/// # Examples
///
/// ```
/// use security_core::context::CorrelationContext;
/// use security_core::types::{RequestId, TraceId, ActorId};
/// use uuid::Uuid;
///
/// let ctx = CorrelationContext::new(RequestId::generate())
///     .with_trace(TraceId::generate())
///     .with_actor(ActorId::from(Uuid::new_v4()));
///
/// assert!(ctx.trace_id().is_some());
/// assert!(ctx.actor_id().is_some());
/// ```
#[must_use]
#[derive(Clone, Debug)]
pub struct CorrelationContext {
    request_id: RequestId,
    trace_id: Option<TraceId>,
    actor_id: Option<ActorId>,
}

impl CorrelationContext {
    /// Creates a new [`CorrelationContext`] with the given request identifier.
    pub fn new(request_id: RequestId) -> Self {
        Self {
            request_id,
            trace_id: None,
            actor_id: None,
        }
    }

    /// Attaches a distributed trace identifier.
    pub fn with_trace(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    /// Attaches the authenticated actor identifier.
    pub fn with_actor(mut self, actor_id: ActorId) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    /// Returns the request identifier.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the trace identifier, if set.
    #[must_use]
    pub fn trace_id(&self) -> Option<&TraceId> {
        self.trace_id.as_ref()
    }

    /// Returns the actor identifier, if set.
    #[must_use]
    pub fn actor_id(&self) -> Option<&ActorId> {
        self.actor_id.as_ref()
    }
}

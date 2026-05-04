//! Security context for enriching events with request-scoped metadata.

use security_core::types::{ActorId, RequestId, TenantId, TraceId};

/// Request-scoped security context used to enrich [`crate::event::SecurityEvent`]s.
///
/// # Examples
///
/// ```
/// use security_events::context::SecurityContext;
/// use security_core::types::RequestId;
///
/// let ctx = SecurityContext::new()
///     .with_request_id(RequestId::generate())
///     .with_session_id("sess-abc".to_string());
/// assert!(ctx.request_id.is_some());
/// ```
#[derive(Clone, Debug, Default)]
pub struct SecurityContext {
    /// Optional inbound request identifier.
    pub request_id: Option<RequestId>,
    /// Optional distributed trace identifier.
    pub trace_id: Option<TraceId>,
    /// Optional authenticated actor identifier.
    pub actor_id: Option<ActorId>,
    /// Optional tenant identifier.
    pub tenant_id: Option<TenantId>,
    /// Optional session identifier.
    pub session_id: Option<String>,
}

impl SecurityContext {
    /// Creates a new empty [`SecurityContext`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a request identifier.
    #[must_use]
    pub fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Attaches a trace identifier.
    #[must_use]
    pub fn with_trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    /// Attaches an actor identifier.
    #[must_use]
    pub fn with_actor_id(mut self, actor_id: ActorId) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    /// Attaches a tenant identifier.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Attaches a session identifier.
    #[must_use]
    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

//! Internal forensic error report.
//!
//! `ErrorReport` carries the full diagnostic context — root cause chain, backtrace,
//! component name, tenant/actor context — that must **never** be sent to clients but
//! **must** be available for security logging (M3).

use security_core::types::{ActorId, RequestId, TenantId};

/// A builder for [`ErrorReport`].
///
/// # Examples
///
/// ```
/// use secure_errors::report::ErrorReport;
///
/// let report = ErrorReport::builder()
///     .cause("database connection refused")
///     .component("user-service")
///     .build();
/// assert_eq!(report.cause(), "database connection refused");
/// assert_eq!(report.component(), "user-service");
/// ```
#[derive(Debug, Default)]
pub struct ErrorReportBuilder {
    cause: String,
    component: Option<&'static str>,
    request_id: Option<RequestId>,
    actor_id: Option<ActorId>,
    tenant_id: Option<TenantId>,
    backtrace: Option<String>,
}

impl ErrorReportBuilder {
    /// Sets the root-cause string (may contain internal details such as SQL text).
    #[must_use]
    pub fn cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = cause.into();
        self
    }

    /// Sets the component name (e.g. `"auth-service"`).
    #[must_use]
    pub fn component(mut self, component: &'static str) -> Self {
        self.component = Some(component);
        self
    }

    /// Attaches a request identifier.
    #[must_use]
    pub fn request_id(mut self, id: RequestId) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Attaches an actor identifier.
    #[must_use]
    pub fn actor_id(mut self, id: ActorId) -> Self {
        self.actor_id = Some(id);
        self
    }

    /// Attaches a tenant identifier.
    #[must_use]
    pub fn tenant_id(mut self, id: TenantId) -> Self {
        self.tenant_id = Some(id);
        self
    }

    /// Captures the current backtrace string.
    #[must_use]
    pub fn with_backtrace(mut self, backtrace: impl Into<String>) -> Self {
        self.backtrace = Some(backtrace.into());
        self
    }

    /// Builds the [`ErrorReport`].
    #[must_use]
    pub fn build(self) -> ErrorReport {
        ErrorReport {
            cause: self.cause,
            component: self.component.unwrap_or("unknown"),
            request_id: self.request_id,
            actor_id: self.actor_id,
            tenant_id: self.tenant_id,
            backtrace: self.backtrace,
        }
    }
}

/// Full forensic context for an error — for internal logging only, never for clients.
#[derive(Debug)]
pub struct ErrorReport {
    /// The root-cause description, which may contain sensitive internal details.
    pub(crate) cause: String,
    /// The component that generated the error.
    pub(crate) component: &'static str,
    /// Request correlation identifier.
    pub(crate) request_id: Option<RequestId>,
    /// Actor identifier, if known.
    pub(crate) actor_id: Option<ActorId>,
    /// Tenant identifier, if known.
    pub(crate) tenant_id: Option<TenantId>,
    /// Captured backtrace, if any.
    pub(crate) backtrace: Option<String>,
}

impl ErrorReport {
    /// Returns a builder.
    #[must_use]
    pub fn builder() -> ErrorReportBuilder {
        ErrorReportBuilder::default()
    }

    /// Returns the root-cause string.
    #[must_use]
    pub fn cause(&self) -> &str {
        &self.cause
    }

    /// Returns the component name.
    #[must_use]
    pub fn component(&self) -> &str {
        self.component
    }

    /// Returns the request identifier, if set.
    #[must_use]
    pub fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Returns the actor identifier, if set.
    #[must_use]
    pub fn actor_id(&self) -> Option<&ActorId> {
        self.actor_id.as_ref()
    }

    /// Returns the tenant identifier, if set.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    /// Returns the captured backtrace string, if any.
    #[must_use]
    pub fn backtrace(&self) -> Option<&str> {
        self.backtrace.as_deref()
    }
}

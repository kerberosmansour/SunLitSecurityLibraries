//! Authorization decision types.

/// The result of an authorization check.
///
/// **Important**: `#[must_use]` — callers cannot silently ignore this.
///
/// # Examples
///
/// ```
/// use secure_authz::decision::{Decision, DenyReason};
///
/// let allow = Decision::Allow { obligations: vec![] };
/// assert!(allow.is_allow());
///
/// let deny = Decision::Deny { reason: DenyReason::InsufficientRole };
/// assert!(deny.is_deny());
/// ```
#[non_exhaustive]
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Access is allowed, potentially with obligations.
    Allow {
        /// Actions or conditions the caller must satisfy after the decision.
        obligations: Vec<String>,
    },
    /// Access is denied with a specific reason.
    Deny {
        /// The reason for the denial.
        reason: DenyReason,
    },
}

impl Decision {
    /// Returns `true` if this decision allows access.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// Returns `true` if this decision denies access.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }
}

/// The reason an authorization request was denied.
///
/// # Examples
///
/// ```
/// use secure_authz::decision::DenyReason;
///
/// let reason = DenyReason::TenantMismatch;
/// assert_eq!(reason, DenyReason::TenantMismatch);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// No policy rule matches the request.
    NoPolicyMatch,
    /// The subject exists but does not have sufficient role for this action.
    InsufficientRole,
    /// The subject and resource belong to different tenants.
    TenantMismatch,
    /// The subject context is incomplete (e.g. empty actor_id).
    IncompleteContext,
    /// The policy engine returned an error.
    EngineError,
    /// Access requires ownership of the resource.
    OwnershipRequired,
    /// The resource descriptor is missing required fields (e.g. no kind).
    MissingResource,
    /// An ABAC predicate failed for the current request attributes.
    AttributeMismatch,
    /// A time-bounded permission is no longer valid.
    PermissionExpired,
    /// A time-bounded permission is not active yet.
    PermissionNotYetActive,
    /// The route requires device trust context, but none was supplied.
    DeviceTrustRequired,
    /// The supplied device trust tier is lower than the route requires.
    DeviceTrustTierTooLow,
    /// Device trust or the bound device session was revoked or denied.
    DeviceTrustRevoked,
    /// Device metadata came from an untrusted edge/header source.
    UntrustedDeviceMetadata,
    /// The user session is not bound to the presented mTLS certificate.
    DeviceSessionBindingMismatch,
    /// A route is restricted to CI/test trust profile callers.
    TestTrustProfileRequired,
}

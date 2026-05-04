//! Device-trust authorization predicates.

use secure_device_trust::{DeviceTrustDecision, DeviceTrustOutcome, TrustTier};
use secure_identity::BoundUserSession;
use secure_network::MtlsClientIdentity;

use crate::action::Action;
use crate::decision::{Decision, DenyReason};
use crate::resource::ResourceRef;

/// Runtime profile for device-trust authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceTrustProfile {
    /// Production route policy.
    Production,
    /// CI or conformance-only route policy.
    Test,
}

/// Device-trust evidence available to authorization.
#[derive(Clone)]
pub struct DeviceTrustContext {
    decision: DeviceTrustDecision,
    mtls: MtlsClientIdentity,
    bound_user_session: Option<BoundUserSession>,
    profile: DeviceTrustProfile,
    revoked_session: bool,
}

impl std::fmt::Debug for DeviceTrustContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTrustContext")
            .field("outcome", &self.decision.outcome())
            .field("tier", &self.decision.tier())
            .field("reasons", &self.decision.reasons())
            .field("mtls_serial", &"<redacted>")
            .field("mtls_fingerprint", &"<redacted>")
            .field("has_bound_user_session", &self.bound_user_session.is_some())
            .field("profile", &self.profile)
            .field("revoked_session", &self.revoked_session)
            .finish()
    }
}

impl DeviceTrustContext {
    /// Creates a device-trust context from a trust decision and mTLS identity.
    #[must_use]
    pub fn new(decision: DeviceTrustDecision, mtls: MtlsClientIdentity) -> Self {
        Self {
            decision,
            mtls,
            bound_user_session: None,
            profile: DeviceTrustProfile::Production,
            revoked_session: false,
        }
    }

    /// Attaches the user session that must be bound to the mTLS identity.
    #[must_use]
    pub fn with_bound_user_session(mut self, session: BoundUserSession) -> Self {
        self.bound_user_session = Some(session);
        self
    }

    /// Selects the route/runtime trust profile.
    #[must_use]
    pub fn with_profile(mut self, profile: DeviceTrustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Marks the current session/device context as revoked.
    #[must_use]
    pub fn with_revoked_session(mut self, revoked_session: bool) -> Self {
        self.revoked_session = revoked_session;
        self
    }

    /// Returns the device-trust decision.
    #[must_use]
    pub fn decision(&self) -> &DeviceTrustDecision {
        &self.decision
    }

    /// Returns the mTLS client identity extracted by a trusted edge.
    #[must_use]
    pub fn mtls(&self) -> &MtlsClientIdentity {
        &self.mtls
    }

    /// Returns the bound user session, if user auth has completed.
    #[must_use]
    pub fn bound_user_session(&self) -> Option<&BoundUserSession> {
        self.bound_user_session.as_ref()
    }

    /// Returns the runtime profile for this context.
    #[must_use]
    pub fn profile(&self) -> DeviceTrustProfile {
        self.profile
    }

    /// Returns true when the session/device context has been revoked.
    #[must_use]
    pub fn is_revoked_session(&self) -> bool {
        self.revoked_session
    }
}

/// Device-trust requirement for a route.
#[derive(Clone, Debug)]
pub struct DeviceTrustRequirement {
    minimum_tier: TrustTier,
    test_profile_only: bool,
    require_bound_user_session: bool,
}

impl DeviceTrustRequirement {
    /// Requires hardware/platform-backed device trust.
    #[must_use]
    pub fn hardware_backed() -> Self {
        Self {
            minimum_tier: TrustTier::HardwareBacked,
            test_profile_only: false,
            require_bound_user_session: true,
        }
    }

    /// Allows software-bound trust only for test/conformance profiles.
    #[must_use]
    pub fn software_bound_test_only() -> Self {
        Self {
            minimum_tier: TrustTier::SoftwareBound,
            test_profile_only: true,
            require_bound_user_session: true,
        }
    }

    /// Allows software-bound trust in production.
    #[must_use]
    pub fn software_bound() -> Self {
        Self {
            minimum_tier: TrustTier::SoftwareBound,
            test_profile_only: false,
            require_bound_user_session: true,
        }
    }

    /// Returns the minimum trust tier.
    #[must_use]
    pub fn minimum_tier(&self) -> TrustTier {
        self.minimum_tier
    }

    /// Returns true when only the test/conformance profile may use this route.
    #[must_use]
    pub fn is_test_profile_only(&self) -> bool {
        self.test_profile_only
    }

    /// Returns true when a bound user session is required.
    #[must_use]
    pub fn requires_bound_user_session(&self) -> bool {
        self.require_bound_user_session
    }
}

/// Device-trust route policy.
#[derive(Clone, Debug)]
pub struct DeviceTrustRoutePolicy {
    action: Action,
    resource: ResourceRef,
    requirement: DeviceTrustRequirement,
}

impl DeviceTrustRoutePolicy {
    /// Creates a route policy for an action/resource pair.
    #[must_use]
    pub fn new(action: Action, resource: ResourceRef, requirement: DeviceTrustRequirement) -> Self {
        Self {
            action,
            resource,
            requirement,
        }
    }

    /// Returns the action guarded by this policy.
    #[must_use]
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// Returns the resource guarded by this policy.
    #[must_use]
    pub fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// Returns the device-trust requirement.
    #[must_use]
    pub fn requirement(&self) -> &DeviceTrustRequirement {
        &self.requirement
    }

    /// Evaluates the route policy against optional device-trust context.
    pub fn evaluate(&self, context: Option<&DeviceTrustContext>) -> Decision {
        evaluate_requirement(context, &self.requirement)
    }
}

fn evaluate_requirement(
    context: Option<&DeviceTrustContext>,
    requirement: &DeviceTrustRequirement,
) -> Decision {
    let Some(context) = context else {
        return deny(DenyReason::DeviceTrustRequired);
    };

    if !context.mtls.trusted_edge {
        return deny(DenyReason::UntrustedDeviceMetadata);
    }

    if context.revoked_session || context.decision.outcome() == DeviceTrustOutcome::Denied {
        return deny(DenyReason::DeviceTrustRevoked);
    }

    if requirement.require_bound_user_session {
        let Some(session) = &context.bound_user_session else {
            return deny(DenyReason::DeviceTrustRequired);
        };
        if !session.is_bound_to(&context.mtls) {
            return deny(DenyReason::DeviceSessionBindingMismatch);
        }
    }

    if requirement.test_profile_only && context.profile != DeviceTrustProfile::Test {
        return deny(DenyReason::TestTrustProfileRequired);
    }

    if context.decision.tier() < requirement.minimum_tier {
        return deny(DenyReason::DeviceTrustTierTooLow);
    }

    Decision::Allow {
        obligations: vec![format!(
            "device-trust:{}",
            trust_tier_label(context.decision.tier())
        )],
    }
}

fn deny(reason: DenyReason) -> Decision {
    Decision::Deny { reason }
}

fn trust_tier_label(tier: TrustTier) -> &'static str {
    match tier {
        TrustTier::None => "none",
        TrustTier::SoftwareBound => "software-bound",
        TrustTier::HardwareBacked => "hardware-backed",
    }
}

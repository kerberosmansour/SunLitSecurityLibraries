//! Framework-neutral enforcement primitives used by both the axum tower
//! [`AuthzLayer`] and the actix-web 4 [`AuthzTransform`].
//!
//! All HTTP-framework-specific adapters reuse [`run_check`] to keep the
//! authorization decision path identical across frameworks (identity-agnostic
//! invariant preserved — `secure_authz` still does not depend on
//! `secure_identity`).
//!
//! [`AuthzLayer`]: crate::middleware::AuthzLayer
//! [`AuthzTransform`]: crate::actix::AuthzTransform

use security_core::identity::AuthenticatedIdentity;

use crate::action::Action;
use crate::decision::Decision;
use crate::enforcer::Authorizer;
use crate::resolver::{DefaultSubjectResolver, SubjectResolver};
use crate::resource::ResourceRef;

/// Marker inserted into request extensions to signal which obligations
/// have been fulfilled for the current request (e.g., `"mfa"`).
///
/// Handlers or prior middleware layers insert this to indicate specific
/// obligations have been satisfied (e.g. MFA verification). Enforcement
/// layers then cross-reference [`Decision::Allow`]'s `obligations` against
/// this set and short-circuit with 403 if any required obligation is
/// missing.
///
/// This type is framework-neutral and lives here so both axum and
/// actix-web adapters can share it.
///
/// # Examples
///
/// ```
/// use secure_authz::enforce::ObligationFulfillment;
///
/// let fulfilled = ObligationFulfillment { fulfilled: vec!["mfa".to_owned()] };
/// assert_eq!(fulfilled.fulfilled.len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct ObligationFulfillment {
    /// Names of obligations that have been fulfilled.
    pub fulfilled: Vec<String>,
}

/// Enforcement outcome emitted by [`run_check`].
///
/// Framework adapters interpret `Allow` as "forward to inner" and `Deny`
/// as "short-circuit with 403".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforceOutcome {
    /// The request is permitted.
    Allow,
    /// The request is denied — return 403.
    Deny,
}

/// Runs the authorization check and obligation reconciliation once, using
/// the same logic from both framework adapters.
///
/// Arguments:
/// - `authorizer` — any implementer of [`Authorizer`].
/// - `identity` — the resolved [`AuthenticatedIdentity`] from request
///   extensions, or `None` if no identity layer ran upstream.
/// - `action`, `resource` — the authz context for this route.
/// - `fulfilled` — obligations reported as fulfilled for this request, if
///   any.
///
/// Returns [`EnforceOutcome::Allow`] if and only if:
/// 1. `identity` is `Some`, AND
/// 2. the authorizer returns [`Decision::Allow`], AND
/// 3. every listed obligation appears in `fulfilled`.
pub async fn run_check<A: Authorizer + ?Sized>(
    authorizer: &A,
    identity: Option<&AuthenticatedIdentity>,
    action: &Action,
    resource: &ResourceRef,
    fulfilled: Option<&ObligationFulfillment>,
) -> EnforceOutcome {
    let Some(identity) = identity else {
        return EnforceOutcome::Deny;
    };
    let subject = DefaultSubjectResolver::resolve(identity);

    match authorizer.authorize(&subject, action, resource).await {
        Decision::Allow { obligations } if obligations.is_empty() => EnforceOutcome::Allow,
        Decision::Allow { obligations } => {
            let fulfilled_names: &[String] =
                fulfilled.map(|f| f.fulfilled.as_slice()).unwrap_or(&[]);
            let all_met = obligations
                .iter()
                .all(|ob| fulfilled_names.iter().any(|f| f == ob));
            if all_met {
                EnforceOutcome::Allow
            } else {
                EnforceOutcome::Deny
            }
        }
        Decision::Deny { .. } => EnforceOutcome::Deny,
    }
}

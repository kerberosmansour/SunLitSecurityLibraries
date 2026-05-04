//! Subject — the actor requesting authorization.
use smallvec::SmallVec;
use std::collections::BTreeMap;

/// The principal requesting authorization.
///
/// Constructed from [`security_core::identity::AuthenticatedIdentity`] via
/// [`crate::resolver::SubjectResolver`].
///
/// # Examples
///
/// ```
/// use secure_authz::subject::Subject;
///
/// let subject = Subject {
///     actor_id: "alice".to_string(),
///     tenant_id: Some("acme".to_string()),
///     roles: smallvec::smallvec!["editor".to_string()],
///     attributes: Default::default(),
/// };
/// assert_eq!(subject.actor_id, "alice");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The unique actor identifier string.
    pub actor_id: String,
    /// The tenant the actor belongs to, if multi-tenancy applies.
    pub tenant_id: Option<String>,
    /// The roles assigned to this actor.
    pub roles: SmallVec<[String; 4]>,
    /// Arbitrary attributes from the identity provider.
    pub attributes: BTreeMap<String, String>,
}

impl Subject {
    /// Returns a subject attribute as `&str` when present.
    #[must_use]
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }
}

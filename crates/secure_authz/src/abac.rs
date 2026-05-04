//! Lightweight attribute-based access control helpers.
//!
//! These helpers let applications express ABAC decisions using ordinary Rust
//! closures rather than introducing a policy language or rule engine.
use std::fmt;
use std::sync::Arc;

use crate::{action::Action, resource::ResourceRef, subject::Subject};

/// A reusable predicate for attribute-based access control.
///
/// The closure returns `true` when the request should be allowed.
///
/// # Examples
///
/// ```
/// use secure_authz::{abac::AttributeGuard, Action, ResourceRef, Subject};
/// use smallvec::smallvec;
/// use std::collections::BTreeMap;
///
/// let subject = Subject {
///     actor_id: "alice".into(),
///     tenant_id: None,
///     roles: smallvec![],
///     attributes: BTreeMap::from([("department".to_string(), "engineering".to_string())]),
/// };
///
/// let guard = AttributeGuard::new(|subject, _, action| {
///     subject.attr("department") == Some("engineering") && matches!(action, Action::Read)
/// });
///
/// assert!(guard.check(&subject, &ResourceRef::new("repo"), &Action::Read));
/// ```
pub type AttributePredicate = Arc<dyn Fn(&Subject, &ResourceRef, &Action) -> bool + Send + Sync>;

/// A composable ABAC guard built from an [`AttributePredicate`].
#[must_use]
#[derive(Clone)]
pub struct AttributeGuard {
    predicate: AttributePredicate,
}

impl fmt::Debug for AttributeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttributeGuard").finish_non_exhaustive()
    }
}

impl AttributeGuard {
    /// Creates a new guard from a Rust closure.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::{abac::AttributeGuard, Action, ResourceRef};
    ///
    /// let guard = AttributeGuard::new(|_, resource, action| {
    ///     resource.kind == "report" && matches!(action, Action::Read)
    /// });
    ///
    /// assert!(guard.check(
    ///     &secure_authz::testkit::test_subject("alice", &[]),
    ///     &ResourceRef::new("report"),
    ///     &Action::Read,
    /// ));
    /// ```
    pub fn new<F>(predicate: F) -> Self
    where
        F: Fn(&Subject, &ResourceRef, &Action) -> bool + Send + Sync + 'static,
    {
        Self {
            predicate: Arc::new(predicate),
        }
    }

    /// Returns a guard that always allows access.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::{abac::AttributeGuard, Action, ResourceRef};
    ///
    /// let guard = AttributeGuard::allow_all();
    /// assert!(guard.check(
    ///     &secure_authz::testkit::test_subject("alice", &[]),
    ///     &ResourceRef::new("anything"),
    ///     &Action::Read,
    /// ));
    /// ```
    pub fn allow_all() -> Self {
        Self::new(|_, _, _| true)
    }

    /// Requires a subject attribute to exactly match the expected value.
    ///
    /// Missing attributes fail closed and therefore deny access.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::{abac::AttributeGuard, Action, ResourceRef};
    ///
    /// let mut subject = secure_authz::testkit::test_subject("alice", &[]);
    /// subject.attributes.insert("role".into(), "admin".into());
    ///
    /// let guard = AttributeGuard::require_subject_attr("role", "admin");
    /// assert!(guard.check(&subject, &ResourceRef::new("dashboard"), &Action::Admin));
    /// ```
    pub fn require_subject_attr(key: impl Into<String>, expected: impl Into<String>) -> Self {
        let key = key.into();
        let expected = expected.into();
        Self::new(move |subject, _, _| subject.attr(&key) == Some(expected.as_str()))
    }

    /// Requires a resource attribute to exactly match the expected value.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::{abac::AttributeGuard, Action, ResourceRef};
    ///
    /// let resource = ResourceRef::new("document").with_attribute("classification", "public");
    /// let guard = AttributeGuard::require_resource_attr("classification", "public");
    ///
    /// assert!(guard.check(
    ///     &secure_authz::testkit::test_subject("alice", &[]),
    ///     &resource,
    ///     &Action::Read,
    /// ));
    /// ```
    pub fn require_resource_attr(key: impl Into<String>, expected: impl Into<String>) -> Self {
        let key = key.into();
        let expected = expected.into();
        Self::new(move |_, resource, _| resource.attr(&key) == Some(expected.as_str()))
    }

    /// Evaluates this guard against the request.
    #[must_use]
    pub fn check(&self, subject: &Subject, resource: &ResourceRef, action: &Action) -> bool {
        (self.predicate)(subject, resource, action)
    }

    /// Combines two guards with logical AND.
    pub fn and(self, other: Self) -> Self {
        Self::new(move |subject, resource, action| {
            self.check(subject, resource, action) && other.check(subject, resource, action)
        })
    }

    /// Combines two guards with logical OR.
    pub fn or(self, other: Self) -> Self {
        Self::new(move |subject, resource, action| {
            self.check(subject, resource, action) || other.check(subject, resource, action)
        })
    }
}

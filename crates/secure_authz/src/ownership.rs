//! Tenant scoping and resource ownership helpers.
use crate::resource::ResourceRef;
use crate::subject::Subject;

/// Returns `true` if the subject owns the resource (actor_id == owner_id).
///
/// # Examples
///
/// ```
/// use secure_authz::ownership::is_owner;
/// use secure_authz::testkit::test_subject;
/// use secure_authz::resource::ResourceRef;
///
/// let subject = test_subject("alice", &[]);
/// let resource = ResourceRef::new("doc").with_owner("alice");
/// assert!(is_owner(&subject, &resource));
/// ```
#[must_use]
pub fn is_owner(subject: &Subject, resource: &ResourceRef) -> bool {
    resource
        .owner_id
        .as_deref()
        .map(|owner_id| subject.actor_id == owner_id)
        .unwrap_or(false)
}

/// Returns `true` if the subject and resource share the same tenant,
/// or the resource has no tenant constraint.
///
/// Cross-tenant access is blocked regardless of policy rules.
///
/// # Examples
///
/// ```
/// use secure_authz::ownership::is_same_tenant;
/// use secure_authz::testkit::test_subject;
/// use secure_authz::resource::ResourceRef;
///
/// let mut subject = test_subject("alice", &[]);
/// subject.tenant_id = Some("acme".into());
/// let resource = ResourceRef::new("doc").with_tenant("acme");
/// assert!(is_same_tenant(&subject, &resource));
/// ```
#[must_use]
pub fn is_same_tenant(subject: &Subject, resource: &ResourceRef) -> bool {
    match (&subject.tenant_id, &resource.tenant_id) {
        (_, None) => true,            // Resource has no tenant — accessible
        (Some(s), Some(r)) => s == r, // Both must match
        (None, Some(_)) => false,     // Subject has no tenant, resource does — deny
    }
}

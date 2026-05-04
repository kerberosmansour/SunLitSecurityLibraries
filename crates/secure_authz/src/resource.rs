//! Resource descriptor types.
use std::collections::BTreeMap;

/// Descriptor for a resource being accessed.
///
/// # Examples
///
/// ```
/// use secure_authz::resource::ResourceRef;
///
/// let resource = ResourceRef::new("article")
///     .with_id("42")
///     .with_tenant("acme")
///     .with_owner("alice");
/// assert_eq!(resource.kind, "article");
/// assert_eq!(resource.resource_id.as_deref(), Some("42"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceRef {
    /// The kind/type of the resource (e.g. `"article"`, `"document"`).
    pub kind: String,
    /// The unique identifier of the specific resource instance.
    pub resource_id: Option<String>,
    /// The tenant this resource belongs to.
    pub tenant_id: Option<String>,
    /// The owner of this resource.
    pub owner_id: Option<String>,
    /// Arbitrary attributes for ABAC evaluation.
    pub attributes: BTreeMap<String, String>,
}

impl ResourceRef {
    /// Creates a new `ResourceRef` with the given kind.
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            ..Default::default()
        }
    }

    /// Attaches a tenant identifier to this resource.
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Attaches an owner identifier to this resource.
    pub fn with_owner(mut self, owner_id: impl Into<String>) -> Self {
        self.owner_id = Some(owner_id.into());
        self
    }

    /// Attaches a resource identifier to this resource.
    pub fn with_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Attaches an arbitrary attribute for ABAC evaluation.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Returns a resource attribute as `&str` when present.
    #[must_use]
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }
}

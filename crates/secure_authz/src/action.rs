//! Typed action enumerations — no role strings in business code.

/// The action being requested on a resource.
///
/// Application code must use these typed variants — never string literals like `"ADMIN"`.
///
/// # Examples
///
/// ```
/// use secure_authz::action::Action;
///
/// let action = Action::Read;
/// assert_eq!(action.to_string(), "read");
///
/// let custom = Action::Custom("export".into());
/// assert_eq!(custom.to_string(), "export");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Delete access.
    Delete,
    /// Create access.
    Create,
    /// Administrative access.
    Admin,
    /// A custom action not covered by the standard variants.
    Custom(String),
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Read => write!(f, "read"),
            Action::Write => write!(f, "write"),
            Action::Delete => write!(f, "delete"),
            Action::Create => write!(f, "create"),
            Action::Admin => write!(f, "admin"),
            Action::Custom(s) => write!(f, "{s}"),
        }
    }
}

//! Canonical ID types for domain identifiers.
//!
//! `TenantId` is re-exported from `security_core`. The types `UserId`, `OrderId`, and
//! `OpaquePublicId` are defined here as distinct newtypes over [`uuid::Uuid`].

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

pub use security_core::types::TenantId;

macro_rules! boundary_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new random ID.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns a reference to the inner [`Uuid`].
            #[must_use]
            pub fn as_inner(&self) -> &Uuid {
                &self.0
            }

            /// Consumes the wrapper and returns the inner [`Uuid`].
            #[must_use]
            pub fn into_inner(self) -> Uuid {
                self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

boundary_id!(
    /// A unique identifier for a user at the boundary layer.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::id::UserId;
    ///
    /// let id = UserId::generate();
    /// let s = id.to_string();
    /// let parsed: UserId = s.parse().unwrap();
    /// assert_eq!(id, parsed);
    /// ```
    UserId
);

boundary_id!(
    /// A unique identifier for an order.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::id::OrderId;
    ///
    /// let id = OrderId::generate();
    /// assert!(!id.to_string().is_empty());
    /// ```
    OrderId
);

boundary_id!(
    /// An opaque public identifier safe for exposure in URLs and API responses.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::id::OpaquePublicId;
    ///
    /// let id = OpaquePublicId::generate();
    /// let inner = id.as_inner();
    /// assert_eq!(inner.get_version_num(), 4);
    /// ```
    OpaquePublicId
);

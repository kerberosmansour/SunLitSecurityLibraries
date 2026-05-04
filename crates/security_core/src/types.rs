#![allow(clippy::module_name_repetitions)]
//! Newtype ID wrappers for domain identifiers.
//!
//! Each type is a distinct newtype over [`uuid::Uuid`] to prevent accidental mixing.
//! `Deref` is intentionally NOT implemented — callers must use `.as_inner()` or `.into_inner()`.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            /// Returns a reference to the inner [`Uuid`].
            #[must_use]
            pub fn as_inner(&self) -> &Uuid {
                &self.0
            }

            /// Consumes the newtype and returns the inner [`Uuid`].
            #[must_use]
            pub fn into_inner(self) -> Uuid {
                self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
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

id_newtype!(
    /// A unique identifier for an actor (user, service account, or system process).
    ///
    /// # Examples
    ///
    /// ```
    /// use security_core::types::ActorId;
    /// use uuid::Uuid;
    ///
    /// let id = ActorId::from(Uuid::new_v4());
    /// assert!(!id.to_string().is_empty());
    /// ```
    ActorId
);
id_newtype!(
    /// A unique identifier for a tenant in a multi-tenant system.
    ///
    /// # Examples
    ///
    /// ```
    /// use security_core::types::TenantId;
    /// use uuid::Uuid;
    ///
    /// let id = TenantId::from(Uuid::new_v4());
    /// assert!(!id.to_string().is_empty());
    /// ```
    TenantId
);
id_newtype!(
    /// A unique identifier for an inbound request.
    ///
    /// # Examples
    ///
    /// ```
    /// use security_core::types::RequestId;
    ///
    /// let id = RequestId::generate();
    /// assert!(!id.to_string().is_empty());
    /// ```
    RequestId
);
id_newtype!(
    /// A distributed trace identifier for correlating spans across services.
    ///
    /// # Examples
    ///
    /// ```
    /// use security_core::types::TraceId;
    ///
    /// let id = TraceId::generate();
    /// assert!(!id.to_string().is_empty());
    /// ```
    TraceId
);
id_newtype!(
    /// A unique identifier for a resource (file, record, object).
    ///
    /// # Examples
    ///
    /// ```
    /// use security_core::types::ResourceId;
    /// use uuid::Uuid;
    ///
    /// let id = ResourceId::from(Uuid::new_v4());
    /// assert!(!id.to_string().is_empty());
    /// ```
    ResourceId
);
id_newtype!(
    /// A unique identifier for a policy version.
    ///
    /// # Examples
    ///
    /// ```
    /// use security_core::types::PolicyVersion;
    /// use uuid::Uuid;
    ///
    /// let v = PolicyVersion::from(Uuid::new_v4());
    /// assert!(!v.to_string().is_empty());
    /// ```
    PolicyVersion
);

impl RequestId {
    /// Generates a new random [`RequestId`].
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl TraceId {
    /// Generates a new random [`TraceId`].
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

//! Actix-web 4 integration for `secure_authz`.
//!
//! Gated on the `actix-web` feature. Ships
//! [`AuthzTransform`](crate::actix::middleware::AuthzTransform), a drop-in
//! equivalent of the axum [`crate::middleware::AuthzLayer`]: reads
//! [`AuthenticatedIdentity`] from request extensions, calls
//! [`crate::enforce::run_check`], and short-circuits with 403 on deny. It also
//! ships [`DeviceTrustTransform`](crate::actix::middleware::DeviceTrustTransform)
//! for route predicates backed by [`crate::device_trust::DeviceTrustContext`].
//!
//! The standard `AuthzTransform` preserves the identity-agnostic invariant.
//! Identity flows in via
//! [`security_core::identity::AuthenticatedIdentity`] stored in the actix
//! request extensions by an upstream auth middleware.
//!
//! # Minimal example
//!
//! ```
//! # #[cfg(feature = "actix-web")]
//! # fn _doc() {
//! use std::sync::Arc;
//! use actix_web::{web, App, HttpResponse};
//! use secure_authz::action::Action;
//! use secure_authz::actix::AuthzTransform;
//! use secure_authz::resource::ResourceRef;
//! use secure_authz::testkit::MockAuthorizer;
//!
//! let authz = Arc::new(MockAuthorizer::allow());
//! let _app = App::new()
//!     .wrap(AuthzTransform::new(
//!         authz,
//!         Action::Read,
//!         ResourceRef::new("item"),
//!     ))
//!     .route("/", web::get().to(|| async { HttpResponse::Ok().finish() }));
//! # }
//! ```
//!
//! See `docs/dev-guide/secure_authz-actix.md` for the full integration guide.
//!
//! [`AuthenticatedIdentity`]: security_core::identity::AuthenticatedIdentity

pub mod middleware;

pub use middleware::{AuthzTransform, DeviceTrustTransform};

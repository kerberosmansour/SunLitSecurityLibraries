#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_authz` — Authorization enforcement (OWASP C7).
//!
//! # Feature Overview
//!
//! The crate ships a framework-neutral core plus optional HTTP framework
//! adapters. Pick one or both:
//!
//! | Feature flag | Default | Enables |
//! |---|---|---|
//! | `axum` | ✅ | [`middleware::AuthzLayer`] as a tower `Layer` |
//! | `actix-web` | | [`actix::AuthzTransform`] as an actix middleware |
//!
//! The standard subject/action/resource authorization path remains
//! identity-agnostic: it depends on
//! [`security_core::identity::AuthenticatedIdentity`]. Identity may come from
//! `secure_identity`, Keycloak, Auth0, or any custom provider.
//!
//! Native device-trust predicates are intentionally typed and live in
//! [`device_trust`]. That module accepts `secure_device_trust`,
//! `secure_identity`, and `secure_network` context so route policies can prove
//! that user sessions stay pinned to verified session mTLS.
//!
//! # What this crate gives you
//!
//! - Typed subjects, actions, and resources (no role strings in business code)
//! - Pluggable policy engine (default: casbin RBAC)
//! - Tenant isolation
//! - Bounded LRU decision cache with TTL
//! - Decision logging to `security_events`
//! - Framework adapters (axum and actix-web 4) that share the same
//!   enforcement pipeline ([`crate::enforce::run_check`]).
//! - Device-trust route predicates for native clients.

pub mod abac;
pub mod action;
pub mod cache;
pub mod decision;
pub mod decision_log;
pub mod device_trust;
pub mod enforce;
pub mod enforcer;
#[cfg(feature = "axum")]
pub mod middleware;
pub mod ownership;
pub mod policy;
pub mod resolver;
pub mod resource;
pub mod subject;
pub mod temporal;
pub mod testing;
pub mod testkit;

/// Actix-web 4 integration — feature-gated via `actix-web`.
#[cfg(feature = "actix-web")]
pub mod actix;

pub use action::Action;
pub use decision::{Decision, DenyReason};
pub use enforcer::{Authorizer, DefaultAuthorizer};
pub use policy::DefaultPolicyEngine;
pub use resolver::{DefaultSubjectResolver, SubjectResolver};
pub use resource::ResourceRef;
pub use subject::Subject;

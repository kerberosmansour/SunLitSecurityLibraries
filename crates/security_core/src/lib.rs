#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `security_core` — Shared types, traits, and abstractions for the SunLit Security Libraries.
//!
//! Every downstream crate depends on this crate for shared identity types, data classification,
//! security severity levels, correlation context, time abstraction, redaction, and identity
//! resolution. This crate contains only types and traits — no business logic, no I/O.

pub mod classification;
pub mod context;
pub mod identity;
pub mod redact;
pub mod severity;
pub mod time;
pub mod types;
pub mod variant_analysis;

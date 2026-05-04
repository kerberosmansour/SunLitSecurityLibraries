#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `security_events` — Security logging, monitoring, and tamper-evident audit (OWASP C9).

pub mod audit_chain;
pub mod context;
pub mod correlation;
pub mod detect;
pub mod emit;
pub mod event;
pub mod hmac;
pub mod kind;
pub mod layer;
pub mod mobile_redaction;
pub mod rate_limit;
pub mod redact;
pub mod sanitize;
pub mod sink;

pub use audit_chain::AuditChain;
pub use correlation::{attach_parent, filter_by_parent, with_parent};
pub use event::{EventOutcome, EventValue, SecurityEvent};
pub use hmac::{HmacError, HmacEventSigner};
pub use kind::EventKind;
pub use mobile_redaction::{LogLevel, LogLevelEnforcer, MobileRedactionEngine};
pub use redact::{RedactionEngine, RedactionPolicy};

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `secure_output` — Output encoding for HTML, JSON, URL, JS, CSS, XML, LDAP, and shell contexts (OWASP C4).
//!
//! Provides the [`OutputEncoder`] open trait and concrete implementations:
//! - [`HtmlEncoder`] — HTML context encoding with zero-copy for safe strings
//! - [`JsonEncoder`] — JSON context encoding preventing `</script>` injection
//! - [`UrlEncoder`] — URL percent-encoding per RFC 3986
//! - [`JsStringEncoder`] — JavaScript string literal encoding
//! - [`CssEncoder`] — CSS context encoding via unicode-escape
//! - [`XmlEncoder`] — XML text/attribute encoding
//! - [`ldap::LdapDnEncoder`] — LDAP Distinguished Name encoding (RFC 4514)
//! - [`ldap::LdapFilterEncoder`] — LDAP search filter encoding (RFC 4515)
//! - [`shell::ShellEncoder`] — POSIX shell argument encoding
//!
//! Also provides:
//! - [`sanitize_uri_scheme()`] — blocks dangerous URI schemes (javascript:, data:, etc.)

pub mod css;
pub mod encode;
pub mod html;
pub mod js;
pub mod json;
pub mod ldap;
pub mod shell;
pub mod uri;
pub mod url;
pub mod xml;

pub use css::CssEncoder;
pub use encode::OutputEncoder;
pub use html::HtmlEncoder;
pub use js::JsStringEncoder;
pub use json::JsonEncoder;
pub use ldap::{LdapDnEncoder, LdapFilterEncoder};
pub use shell::ShellEncoder;
pub use uri::{sanitize_uri_scheme, DangerousUriScheme};
pub use url::UrlEncoder;
pub use xml::XmlEncoder;

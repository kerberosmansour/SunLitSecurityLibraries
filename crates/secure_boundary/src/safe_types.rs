//! Type-safe input wrappers that reject dangerous values at construction time.
//!
//! Every type validates in both [`TryFrom<&str>`] and [`serde::Deserialize`].
//! Invalid input emits a [`BoundaryViolation`] security event before rejection.
//! No `Deref` is implemented — callers must use `as_inner()` / `into_inner()`.

use crate::{
    attack_signal::{BoundaryViolation, ViolationKind},
    error::BoundaryRejection,
};
use serde::{Deserialize, Deserializer};
use std::fmt;

// ── Internal helpers ──────────────────────────────────────────────────────────

fn emit_violation(kind: ViolationKind, code: &'static str) {
    BoundaryViolation::new(kind, code).emit();
}

// ── SafePath ──────────────────────────────────────────────────────────────────

/// A validated relative file-system path.
///
/// Rejects directory traversal (`../`, `..\`), absolute paths, null bytes,
/// and percent-encoded traversal sequences.
///
/// # Examples
///
/// ```
/// use secure_boundary::safe_types::SafePath;
///
/// let path = SafePath::try_from("uploads/photo.jpg").unwrap();
/// assert_eq!(path.as_inner(), "uploads/photo.jpg");
///
/// // Traversal attempts are rejected.
/// assert!(SafePath::try_from("../../etc/passwd").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SafePath(String);

impl SafePath {
    /// Returns a reference to the inner path string.
    #[must_use]
    pub fn as_inner(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner path string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for SafePath {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.contains('\0') {
            emit_violation(ViolationKind::SyntaxViolation, "path_traversal");
            return Err(BoundaryRejection::PathTraversal);
        }
        if s.starts_with('/') || s.starts_with('\\') {
            emit_violation(ViolationKind::SyntaxViolation, "path_traversal");
            return Err(BoundaryRejection::PathTraversal);
        }
        if s.contains("../")
            || s.contains("..\\")
            || s == ".."
            || s.ends_with("/..")
            || s.ends_with("\\..")
        {
            emit_violation(ViolationKind::SyntaxViolation, "path_traversal");
            return Err(BoundaryRejection::PathTraversal);
        }
        // Reject percent-encoded traversal sequences
        let lower = s.to_lowercase();
        if lower.contains("%2e%2e")
            || lower.contains("%2f")
            || lower.contains("%5c")
            || lower.contains("..%2f")
            || lower.contains("..%5c")
        {
            emit_violation(ViolationKind::SyntaxViolation, "path_traversal");
            return Err(BoundaryRejection::PathTraversal);
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SafePath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SafePath::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SafePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SafeFilename ──────────────────────────────────────────────────────────────

/// A validated filename (no path separators, shell metacharacters, or traversal).
///
/// # Examples
///
/// ```
/// use secure_boundary::safe_types::SafeFilename;
///
/// let name = SafeFilename::try_from("report.pdf").unwrap();
/// assert_eq!(name.as_inner(), "report.pdf");
///
/// assert!(SafeFilename::try_from("../evil").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SafeFilename(String);

impl SafeFilename {
    /// Returns a reference to the inner filename string.
    #[must_use]
    pub fn as_inner(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner filename string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for SafeFilename {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let reject = || {
            emit_violation(ViolationKind::SyntaxViolation, "invalid_filename");
            BoundaryRejection::InjectionAttempt {
                code: "invalid_filename",
            }
        };
        if s.is_empty() {
            return Err(reject());
        }
        if s.contains('\0') {
            return Err(reject());
        }
        if s.contains('/') || s.contains('\\') {
            return Err(reject());
        }
        if s == ".." || s.starts_with("../") || s.starts_with("..\\") {
            return Err(reject());
        }
        // Shell metacharacters
        if s.chars()
            .any(|c| matches!(c, ';' | '|' | '&' | '`' | '$' | '>' | '<'))
        {
            return Err(reject());
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SafeFilename {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SafeFilename::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SafeFilename {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SafeCommandArg ────────────────────────────────────────────────────────────

/// A validated command-line argument with shell injection characters rejected.
///
/// # Examples
///
/// ```
/// use secure_boundary::safe_types::SafeCommandArg;
///
/// let arg = SafeCommandArg::try_from("backup-2024").unwrap();
/// assert_eq!(arg.as_inner(), "backup-2024");
///
/// assert!(SafeCommandArg::try_from("file; rm -rf /").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SafeCommandArg(String);

impl SafeCommandArg {
    /// Returns a reference to the inner argument string.
    #[must_use]
    pub fn as_inner(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner argument string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for SafeCommandArg {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let reject = || {
            emit_violation(ViolationKind::SyntaxViolation, "command_injection");
            BoundaryRejection::InjectionAttempt {
                code: "command_injection",
            }
        };
        if s.chars()
            .any(|c| matches!(c, ';' | '|' | '&' | '`' | '$' | '>' | '<' | '\n' | '\r'))
        {
            return Err(reject());
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SafeCommandArg {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SafeCommandArg::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SafeCommandArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SafeUrl ───────────────────────────────────────────────────────────────────

/// A validated URL that rejects dangerous schemes and URLs resolving to
/// network ranges that enable server-side request forgery.
///
/// # Allowed schemes
/// Only `http` and `https`. Rejects `file://`, `gopher://`, `javascript:`,
/// `data:`, and any other non-http(s) scheme.
///
/// # Blocked host ranges (SSRF prevention)
///
/// Every URL whose host string parses as one of the following IP families
/// is rejected with [`BoundaryRejection::SsrfAttempt`]:
///
/// | CIDR | What it is | Why it's blocked |
/// |---|---|---|
/// | `10.0.0.0/8` | RFC 1918 private | Classic LAN SSRF |
/// | `172.16.0.0/12` | RFC 1918 private | Classic LAN SSRF |
/// | `192.168.0.0/16` | RFC 1918 private | Classic LAN SSRF |
/// | `169.254.0.0/16` | IPv4 link-local | AWS IMDS (`169.254.169.254`) — credential exfiltration |
/// | `127.0.0.0/8` | IPv4 loopback | Bypass to localhost services |
/// | `224.0.0.0/4` | IPv4 multicast | Lateral-movement response surface |
/// | `0.0.0.0/32` | IPv4 unspecified | Stack-internal vulnerabilities |
/// | `fc00::/7` | IPv6 Unique Local Address | Analogue of RFC 1918 on IPv6 |
/// | `fe80::/10` | IPv6 link-local | IPv6 analogue of IMDS attack vector |
/// | `::1/128` | IPv6 loopback | Bypass to localhost services on IPv6 |
/// | `ff00::/8` | IPv6 multicast | Same as IPv4 multicast, on IPv6 |
/// | `::/128` | IPv6 unspecified | Stack-internal vulnerabilities |
///
/// IPv4-mapped IPv6 literals such as `[::ffff:127.0.0.1]` are classified
/// against the embedded IPv4 address before the IPv6 ranges are checked.
///
/// The blocked set is variant-analysis-tested — each CIDR has a named
/// regression test in `sg_gate_a_safeurl_cidrs.rs`, so removing a single
/// line from the internal classifier fails a specific, named test.
///
/// DNS rebinding is **not** prevented by `SafeUrl` alone; validate only
/// accepts a host *string*. If you resolve and connect, perform a fresh
/// `is_private_ip` check on the resolved address, or pin to a specific
/// resolver policy.
///
/// # Examples
///
/// ```
/// use secure_boundary::safe_types::SafeUrl;
///
/// // Public URL — accepted.
/// let url = SafeUrl::try_from("https://example.com/api").unwrap();
/// assert_eq!(url.as_inner(), "https://example.com/api");
///
/// // Loopback — rejected.
/// assert!(SafeUrl::try_from("http://127.0.0.1/admin").is_err());
///
/// // AWS IMDS — rejected.
/// assert!(SafeUrl::try_from("http://169.254.169.254/latest/meta-data").is_err());
///
/// // IPv6 link-local — rejected.
/// assert!(SafeUrl::try_from("http://[fe80::1]/").is_err());
///
/// // Dangerous scheme — rejected.
/// assert!(SafeUrl::try_from("javascript:alert(1)").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SafeUrl(String);

impl SafeUrl {
    /// Returns a reference to the inner URL string.
    #[must_use]
    pub fn as_inner(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner URL string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for SafeUrl {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let reject = || {
            emit_violation(ViolationKind::SyntaxViolation, "ssrf_attempt");
            BoundaryRejection::SsrfAttempt
        };

        let lower = s.to_lowercase();

        let is_http = lower.starts_with("http://");
        let is_https = lower.starts_with("https://");

        if !is_http && !is_https {
            return Err(reject());
        }

        let prefix_len = if is_https {
            "https://".len()
        } else {
            "http://".len()
        };
        let rest = &s[prefix_len..];
        let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..host_end];
        let host_with_port = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host_port)| host_port);

        // Strip IPv6 brackets or port suffix
        let host = if host_with_port.starts_with('[') {
            // IPv6: [::1] or [::1]:8080
            let bracket_end = host_with_port
                .find(']')
                .map(|i| i + 1)
                .unwrap_or(host_with_port.len());
            &host_with_port[..bracket_end]
        } else {
            // IPv4 or hostname: strip port
            match host_with_port.rfind(':') {
                Some(pos)
                    if host_with_port[pos + 1..]
                        .chars()
                        .all(|c| c.is_ascii_digit()) =>
                {
                    &host_with_port[..pos]
                }
                _ => host_with_port,
            }
        };

        if is_private_ip(host) {
            return Err(reject());
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SafeUrl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SafeUrl::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SafeUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_private_ip(host: &str) -> bool {
    // Strip IPv6 brackets for parsing
    let host = host.trim_matches(|c| c == '[' || c == ']');

    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        return is_private_ipv4(addr);
    }
    if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        return is_private_ipv6(addr);
    }
    false
}

fn is_private_ipv4(addr: std::net::Ipv4Addr) -> bool {
    let o = addr.octets();
    // 127.0.0.0/8  loopback
    o[0] == 127
    // 10.0.0.0/8
    || o[0] == 10
    // 172.16.0.0/12
    || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
    // 192.168.0.0/16
    || (o[0] == 192 && o[1] == 168)
    // 169.254.0.0/16  link-local (AWS IMDS 169.254.169.254 and neighbours)
    || (o[0] == 169 && o[1] == 254)
    // 224.0.0.0/4  IPv4 multicast (lateral-movement response surface)
    || (o[0] >= 224 && o[0] <= 239)
    // 0.0.0.0/32  unspecified
    || (o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0)
}

fn is_private_ipv6(addr: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = addr.to_ipv4_mapped() {
        return is_private_ipv4(v4);
    }

    // ::1/128 loopback
    addr.is_loopback()
    // ::/128 unspecified
    || addr.is_unspecified()
    // fc00::/7 unique local
    || (addr.segments()[0] & 0xfe00) == 0xfc00
    // fe80::/10 link-local (IPv6 analogue of the IMDS attack vector)
    || (addr.segments()[0] & 0xffc0) == 0xfe80
    // ff00::/8 multicast
    || (addr.segments()[0] & 0xff00) == 0xff00
}

// ── SafeRedirectUrl ───────────────────────────────────────────────────────────

/// A validated redirect URL that only allows relative paths (no open redirect).
///
/// Must start with `/` but not `//`, and must not contain a scheme colon.
///
/// # Examples
///
/// ```
/// use secure_boundary::safe_types::SafeRedirectUrl;
///
/// let url = SafeRedirectUrl::try_from("/dashboard").unwrap();
/// assert_eq!(url.as_inner(), "/dashboard");
///
/// // External URLs are rejected (open redirect prevention).
/// assert!(SafeRedirectUrl::try_from("//evil.com").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SafeRedirectUrl(String);

impl SafeRedirectUrl {
    /// Returns a reference to the inner URL string.
    #[must_use]
    pub fn as_inner(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner URL string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for SafeRedirectUrl {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let reject = || {
            emit_violation(ViolationKind::SyntaxViolation, "invalid_redirect");
            BoundaryRejection::InjectionAttempt {
                code: "invalid_redirect",
            }
        };
        // Must be a relative path starting with /
        if !s.starts_with('/') || s.starts_with("//") {
            return Err(reject());
        }
        // No scheme separator allowed
        if s.contains(':') {
            return Err(reject());
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SafeRedirectUrl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SafeRedirectUrl::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SafeRedirectUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SqlIdentifier ─────────────────────────────────────────────────────────────

/// A validated SQL identifier (alphanumeric + underscore, max 128 chars).
///
/// Rejects anything that is not a valid SQL identifier: must start with a letter
/// or underscore, must contain only `[A-Za-z0-9_]`, maximum 128 characters.
///
/// # Examples
///
/// ```
/// use secure_boundary::safe_types::SqlIdentifier;
///
/// let id = SqlIdentifier::try_from("users_table").unwrap();
/// assert_eq!(id.as_inner(), "users_table");
///
/// assert!(SqlIdentifier::try_from("DROP TABLE;").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SqlIdentifier(String);

impl SqlIdentifier {
    /// Returns a reference to the inner identifier string.
    #[must_use]
    pub fn as_inner(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner identifier string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for SqlIdentifier {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let reject = || {
            emit_violation(ViolationKind::SyntaxViolation, "invalid_sql_identifier");
            BoundaryRejection::InjectionAttempt {
                code: "invalid_sql_identifier",
            }
        };
        if s.is_empty() {
            return Err(reject());
        }
        if s.len() > 128 {
            return Err(reject());
        }
        let mut chars = s.chars();
        let first = chars.next().expect("non-empty string has a first char");
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(reject());
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(reject());
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SqlIdentifier {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SqlIdentifier::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SqlIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── LdapSafeString ────────────────────────────────────────────────────────────

/// An LDAP-safe string with RFC 4515 escaping applied to special characters.
///
/// Special characters (`*`, `(`, `)`, `\`, NUL) are escaped to their `\xx`
/// hex form. The construction always succeeds; a [`BoundaryViolation`] event is
/// emitted when escaping was necessary (potential injection signal).
///
/// # Examples
///
/// ```
/// use secure_boundary::safe_types::LdapSafeString;
///
/// let s = LdapSafeString::try_from("user*(admin)").unwrap();
/// assert_eq!(s.as_inner(), "user\\2a\\28admin\\29");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LdapSafeString(String);

impl LdapSafeString {
    /// Returns a reference to the RFC 4515-escaped string.
    #[must_use]
    pub fn as_inner(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the RFC 4515-escaped string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for LdapSafeString {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let mut escaped = String::with_capacity(s.len() * 2);
        let mut had_special = false;

        for c in s.chars() {
            match c {
                '\0' => {
                    escaped.push_str("\\00");
                    had_special = true;
                }
                '*' => {
                    escaped.push_str("\\2a");
                    had_special = true;
                }
                '(' => {
                    escaped.push_str("\\28");
                    had_special = true;
                }
                ')' => {
                    escaped.push_str("\\29");
                    had_special = true;
                }
                '\\' => {
                    escaped.push_str("\\5c");
                    had_special = true;
                }
                other => escaped.push(other),
            }
        }

        if had_special {
            emit_violation(ViolationKind::SyntaxViolation, "ldap_injection_chars");
        }

        Ok(Self(escaped))
    }
}

impl<'de> Deserialize<'de> for LdapSafeString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        // TryFrom never returns Err for LdapSafeString, but we still use the
        // unified pattern for consistency.
        LdapSafeString::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for LdapSafeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

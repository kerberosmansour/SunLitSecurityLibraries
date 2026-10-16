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

/// A canonical URL that rejects dangerous schemes and protected literal hosts
/// that enable server-side request forgery.
///
/// # Allowed schemes
/// Only `http` and `https`. Rejects `file://`, `gopher://`, `javascript:`,
/// `data:`, and any other non-http(s) scheme.
///
/// # Public-address policy (SSRF prevention)
///
/// The input is parsed with the WHATWG `url` model and the same canonical value
/// that was classified is retained. Credentials, fragments and backslashes are
/// rejected. Typed IP hosts are accepted only when they are public unicast
/// addresses. The following non-global and special-purpose families are rejected
/// with [`BoundaryRejection::SsrfAttempt`]:
///
/// | CIDR | What it is | Why it's blocked |
/// |---|---|---|
/// | `10.0.0.0/8` | RFC 1918 private | Classic LAN SSRF |
/// | `100.64.0.0/10` | Shared address space | Carrier-grade NAT and provider metadata |
/// | `172.16.0.0/12` | RFC 1918 private | Classic LAN SSRF |
/// | `192.168.0.0/16` | RFC 1918 private | Classic LAN SSRF |
/// | `169.254.0.0/16` | IPv4 link-local | AWS IMDS (`169.254.169.254`) — credential exfiltration |
/// | `127.0.0.0/8` | IPv4 loopback | Bypass to localhost services |
/// | `0.0.0.0/8` | Current network / unspecified | Stack-internal behavior |
/// | `192.0.0.0/24` | IETF protocol assignments | Special-purpose endpoints |
/// | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Documentation | Non-routable examples |
/// | `192.31.196.0/24`, `192.52.193.0/24`, `192.88.99.0/24`, `192.175.48.0/24` | IANA special-purpose | Anycast and transition infrastructure |
/// | `198.18.0.0/15` | Benchmarking | Non-public test networks |
/// | `224.0.0.0/4` | IPv4 multicast | Lateral-movement response surface |
/// | `240.0.0.0/4` | Reserved / broadcast | Non-public destinations |
/// | outside IPv6 `2000::/3` | Non-global-unicast IPv6 | Loopback, local, multicast and reserved space |
/// | IPv6 `2001::/23`, `2001:db8::/32`, `2002::/16`, `3fff::/20` | Special-purpose, documentation and 6to4 | Ambiguous or non-public destinations |
///
/// IPv4-mapped IPv6 literals such as `[::ffff:127.0.0.1]` are classified
/// against the embedded IPv4 address before the IPv6 ranges are checked.
///
/// The original Gate A ranges retain named regression tests. Additional tests
/// exercise shared, documentation, benchmarking, reserved, IPv6 special-purpose
/// and provider-metadata addresses through both literal and resolved-IP paths.
///
/// DNS rebinding is **not** prevented by construction alone. Resolve with a
/// bounded policy, pass every answer to [`SafeUrl::validate_resolved_ip`], and
/// pin an approved address through connection establishment.
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

    /// Applies the same protected-address policy to an address returned by DNS.
    ///
    /// Callers that resolve hostnames must check every answer and pin an
    /// approved address through connection establishment to prevent rebinding.
    ///
    /// # Errors
    ///
    /// Returns [`BoundaryRejection::SsrfAttempt`] for a protected address.
    pub fn validate_resolved_ip(addr: std::net::IpAddr) -> Result<(), BoundaryRejection> {
        if is_non_global_ip_addr(addr) {
            emit_violation(ViolationKind::SyntaxViolation, "ssrf_attempt");
            return Err(BoundaryRejection::SsrfAttempt);
        }
        Ok(())
    }
}

impl TryFrom<&str> for SafeUrl {
    type Error = BoundaryRejection;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let reject = || {
            emit_violation(ViolationKind::SyntaxViolation, "ssrf_attempt");
            BoundaryRejection::SsrfAttempt
        };

        if s.contains('\\') {
            return Err(reject());
        }

        let parsed = url::Url::parse(s).map_err(|_| reject())?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(reject());
        }

        let protected = match parsed.host().expect("host checked above") {
            url::Host::Ipv4(addr) => is_non_global_ipv4(addr),
            url::Host::Ipv6(addr) => is_non_global_ipv6(addr),
            url::Host::Domain(_) => false,
        };
        if protected {
            return Err(reject());
        }

        Ok(Self(parsed.to_string()))
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

fn is_non_global_ip_addr(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(addr) => is_non_global_ipv4(addr),
        std::net::IpAddr::V6(addr) => is_non_global_ipv6(addr),
    }
}

fn is_non_global_ipv4(addr: std::net::Ipv4Addr) -> bool {
    let o = addr.octets();
    // 0.0.0.0/8  current network and unspecified addresses
    o[0] == 0
    // 10.0.0.0/8
    || o[0] == 10
    // 100.64.0.0/10  shared address space, including provider metadata endpoints
    || (o[0] == 100 && (64..=127).contains(&o[1]))
    // 127.0.0.0/8  loopback
    || o[0] == 127
    // 172.16.0.0/12
    || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
    // 169.254.0.0/16  link-local (AWS IMDS 169.254.169.254 and neighbours)
    || (o[0] == 169 && o[1] == 254)
    // 192.0.0.0/24  IETF protocol assignments
    || (o[0] == 192 && o[1] == 0 && o[2] == 0)
    // 192.0.2.0/24  documentation
    || (o[0] == 192 && o[1] == 0 && o[2] == 2)
    // Additional IANA special-purpose anycast and transition ranges.
    || (o[0] == 192
        && matches!((o[1], o[2]), (31, 196) | (52, 193) | (88, 99) | (175, 48)))
    // 192.168.0.0/16
    || (o[0] == 192 && o[1] == 168)
    // 198.18.0.0/15  benchmarking
    || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
    // 198.51.100.0/24  documentation
    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
    // 203.0.113.0/24  documentation
    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    // 224.0.0.0/4  IPv4 multicast (lateral-movement response surface)
    || (o[0] >= 224 && o[0] <= 239)
    // 240.0.0.0/4  reserved, including the limited broadcast address
    || o[0] >= 240
}

fn is_non_global_ipv6(addr: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = addr.to_ipv4_mapped() {
        return is_non_global_ipv4(v4);
    }

    let segments = addr.segments();

    // Accept only the global-unicast allocation 2000::/3, then exclude the
    // special-purpose allocations inside it. This deliberately fails closed
    // as IANA assigns new ranges; updating the policy requires regression
    // evidence rather than silently permitting a newly meaningful address.
    (segments[0] & 0xe000) != 0x2000
    // 2001::/23  protocol assignments and special-purpose ranges.
    || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
    // 2001:db8::/32  documentation (also covered above, kept explicit).
    || (segments[0] == 0x2001 && segments[1] == 0x0db8)
    // 2002::/16  6to4 embeds an IPv4 destination and is not accepted here.
    || segments[0] == 0x2002
    // 3fff::/20  documentation.
    || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
}

// ── SafeRedirectUrl ───────────────────────────────────────────────────────────

/// A validated redirect URL that only allows relative paths (no open redirect).
///
/// Must resolve as a canonical same-origin path under a fixed HTTPS base.
/// Network paths, backslashes, raw control/whitespace characters, malformed
/// percent escapes and encoded path separators are rejected.
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
        // Reject parser differentials before URL normalization. Encoded path
        // separators and controls are rejected as well because downstream
        // frameworks may decode them before applying redirect semantics.
        if !s.starts_with('/')
            || s.starts_with("//")
            || s.contains('\\')
            || s.bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || has_unsafe_percent_escape(s)
        {
            return Err(reject());
        }

        // Preserve the existing no-colon contract so callers cannot smuggle a
        // scheme-like value through a framework with different parsing rules.
        if s.contains(':') {
            return Err(reject());
        }

        let base = url::Url::parse("https://safe.invalid/").map_err(|_| reject())?;
        let parsed = base.join(s).map_err(|_| reject())?;
        if parsed.scheme() != "https"
            || parsed.host_str() != Some("safe.invalid")
            || parsed.port().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path().starts_with("//")
        {
            return Err(reject());
        }

        let mut canonical = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            canonical.push('?');
            canonical.push_str(query);
        }
        if let Some(fragment) = parsed.fragment() {
            canonical.push('#');
            canonical.push_str(fragment);
        }
        Ok(Self(canonical))
    }
}

fn has_unsafe_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return true;
        }
        let Some(high) = hex_value(bytes[index + 1]) else {
            return true;
        };
        let Some(low) = hex_value(bytes[index + 2]) else {
            return true;
        };
        let decoded = (high << 4) | low;
        if decoded.is_ascii_control() || matches!(decoded, b'/' | b'\\' | 0x7f) {
            return true;
        }
        index += 3;
    }
    false
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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

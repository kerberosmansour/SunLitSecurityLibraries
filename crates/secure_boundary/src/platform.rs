//! Mobile platform interaction safety types (MASVS-PLATFORM).
//!
//! Provides:
//! - [`SafeDeepLink`] — validated deep link / universal link URL
//! - [`ClipboardPolicy`] — clipboard security policy based on data classification
//! - [`SafeWebViewUrl`] — validated WebView target URL
//! - [`ScreenshotPolicy`] — screenshot prevention signal
//!
//! All types are pure Rust with no platform SDK dependencies.
//! Platform-level enforcement happens in the consuming mobile application.
//!
//! Feature-gated behind `mobile-platform`.

use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use std::fmt;

// ── Dangerous schemes blocked unconditionally ────────────────────────────────

const DANGEROUS_SCHEMES: &[&str] = &["javascript", "data", "blob", "vbscript"];

// ── PlatformRejection ────────────────────────────────────────────────────────

/// Rejection reasons for mobile platform safety validation.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformRejection {
    /// The URL scheme is not in the allowed list.
    InvalidScheme,
    /// The URL uses a dangerous scheme (javascript:, data:, blob:, vbscript:).
    DangerousScheme,
    /// A path traversal sequence was detected in the URL.
    PathTraversal,
    /// The URL host is not in the trusted host list.
    UntrustedHost,
    /// A file:// URL was blocked in WebView context.
    FileAccessBlocked,
    /// The URL could not be parsed.
    MalformedUrl,
}

impl fmt::Display for PlatformRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScheme => write!(f, "URL scheme not in allowed list"),
            Self::DangerousScheme => write!(f, "dangerous URL scheme blocked"),
            Self::PathTraversal => write!(f, "path traversal detected in URL"),
            Self::UntrustedHost => write!(f, "URL host not in trusted list"),
            Self::FileAccessBlocked => write!(f, "file:// URL blocked in WebView"),
            Self::MalformedUrl => write!(f, "malformed URL"),
        }
    }
}

impl std::error::Error for PlatformRejection {}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn extract_scheme(url: &str) -> Option<&str> {
    let colon = url.find(':')?;
    let scheme = &url[..colon];
    if scheme.is_empty() {
        return None;
    }
    // Schemes must be ASCII alphabetic (possibly with +, -, .)
    if scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        Some(scheme)
    } else {
        None
    }
}

fn extract_host(url: &str) -> Option<&str> {
    let after_scheme = url.find("://").map(|i| i + 3)?;
    let rest = &url[after_scheme..];
    if rest.is_empty() {
        return None;
    }
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host_with_port = &rest[..host_end];
    // Strip port
    let host = match host_with_port.rfind(':') {
        Some(pos)
            if host_with_port[pos + 1..]
                .chars()
                .all(|c| c.is_ascii_digit()) =>
        {
            &host_with_port[..pos]
        }
        _ => host_with_port,
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn has_path_traversal(url: &str) -> bool {
    // Check the path portion after scheme://host
    let path = if let Some(idx) = url.find("://") {
        let after = &url[idx + 3..];
        after.find('/').map(|i| &after[i..]).unwrap_or("")
    } else if let Some(idx) = url.find(':') {
        &url[idx + 1..]
    } else {
        url
    };
    path.contains("../")
        || path.contains("..\\")
        || path == ".."
        || path.ends_with("/..")
        || path.ends_with("\\..")
        || {
            let lower = path.to_lowercase();
            lower.contains("%2e%2e") || lower.contains("..%2f") || lower.contains("..%5c")
        }
}

fn is_dangerous_scheme(scheme: &str) -> bool {
    let lower = scheme.to_lowercase();
    DANGEROUS_SCHEMES.iter().any(|&s| lower == s)
}

fn make_violation_event() -> SecurityEvent {
    SecurityEvent::new(
        EventKind::PlatformSafetyViolation,
        SecuritySeverity::High,
        EventOutcome::Blocked,
    )
}

// ── SafeDeepLink ─────────────────────────────────────────────────────────────

/// A validated deep link / universal link URL.
///
/// Constructed via [`DeepLinkValidator`], which enforces allowed schemes,
/// optional host allowlists, and blocks dangerous schemes and path traversal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SafeDeepLink(String);

impl SafeDeepLink {
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

impl fmt::Display for SafeDeepLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── DeepLinkValidator ────────────────────────────────────────────────────────

/// Validates deep link / universal link URLs against configurable policies.
///
/// # Examples
///
/// ```
/// use secure_boundary::platform::DeepLinkValidator;
///
/// let validator = DeepLinkValidator::new(&["myapp"]);
/// let link = validator.validate("myapp://profile/123").unwrap();
/// assert_eq!(link.as_inner(), "myapp://profile/123");
/// ```
#[derive(Clone, Debug)]
pub struct DeepLinkValidator {
    allowed_schemes: Vec<String>,
    allowed_hosts: Option<Vec<String>>,
}

impl DeepLinkValidator {
    /// Creates a new validator with the given allowed URL schemes.
    #[must_use]
    pub fn new(allowed_schemes: &[&str]) -> Self {
        Self {
            allowed_schemes: allowed_schemes.iter().map(|s| s.to_lowercase()).collect(),
            allowed_hosts: None,
        }
    }

    /// Adds a host allowlist. When set, only URLs with matching hosts are accepted.
    #[must_use]
    pub fn with_allowed_hosts(mut self, hosts: &[&str]) -> Self {
        self.allowed_hosts = Some(hosts.iter().map(|h| h.to_lowercase()).collect());
        self
    }

    /// Validates a URL and returns a [`SafeDeepLink`] or a [`PlatformRejection`].
    pub fn validate(&self, url: &str) -> Result<SafeDeepLink, PlatformRejection> {
        let scheme = extract_scheme(url).ok_or(PlatformRejection::MalformedUrl)?;

        // Block dangerous schemes first (before checking allowed list)
        if is_dangerous_scheme(scheme) {
            return Err(PlatformRejection::DangerousScheme);
        }

        // Check allowed schemes
        if !self.allowed_schemes.contains(&scheme.to_lowercase()) {
            return Err(PlatformRejection::InvalidScheme);
        }

        // Check path traversal
        if has_path_traversal(url) {
            return Err(PlatformRejection::PathTraversal);
        }

        // Check host allowlist if configured
        if let Some(ref allowed_hosts) = self.allowed_hosts {
            let host = extract_host(url).ok_or(PlatformRejection::UntrustedHost)?;
            if !allowed_hosts.contains(&host.to_lowercase()) {
                return Err(PlatformRejection::UntrustedHost);
            }
        }

        Ok(SafeDeepLink(url.to_owned()))
    }

    /// Validates a URL, returning both the result and any security events emitted.
    pub fn validate_with_events(
        &self,
        url: &str,
    ) -> (Result<SafeDeepLink, PlatformRejection>, Vec<SecurityEvent>) {
        let result = self.validate(url);
        let events = if result.is_err() {
            vec![make_violation_event()]
        } else {
            vec![]
        };
        (result, events)
    }
}

// ── ClipboardPolicy ──────────────────────────────────────────────────────────

/// Clipboard security policy based on data classification.
///
/// Determines whether clipboard content should be restricted to the local device
/// and whether it should auto-expire.
///
/// # Examples
///
/// ```
/// use secure_boundary::platform::ClipboardPolicy;
/// use security_core::classification::DataClassification;
///
/// let policy = ClipboardPolicy::for_classification(DataClassification::Secret);
/// assert!(policy.restrict_to_local_device());
/// assert_eq!(policy.expiration_seconds(), Some(60));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipboardPolicy {
    local_only: bool,
    expiration_secs: Option<u64>,
}

impl ClipboardPolicy {
    /// Creates a clipboard policy appropriate for the given data classification.
    ///
    /// - `Public` / `Internal`: no restrictions
    /// - `Confidential` and above: restrict to local device
    /// - `Secret` / `Credentials`: 60-second expiration
    #[must_use]
    pub fn for_classification(class: DataClassification) -> Self {
        match class {
            DataClassification::Public | DataClassification::Internal => Self {
                local_only: false,
                expiration_secs: None,
            },
            DataClassification::Confidential
            | DataClassification::PII
            | DataClassification::Regulated => Self {
                local_only: true,
                expiration_secs: None,
            },
            DataClassification::Secret | DataClassification::Credentials => Self {
                local_only: true,
                expiration_secs: Some(60),
            },
            _ => Self {
                local_only: true,
                expiration_secs: Some(60),
            },
        }
    }

    /// Returns `true` if clipboard content should be restricted to the local device.
    #[must_use]
    pub fn restrict_to_local_device(&self) -> bool {
        self.local_only
    }

    /// Returns the auto-expiration time in seconds, if any.
    #[must_use]
    pub fn expiration_seconds(&self) -> Option<u64> {
        self.expiration_secs
    }
}

// ── SafeWebViewUrl ───────────────────────────────────────────────────────────

/// A validated WebView target URL.
///
/// Constructed via [`WebViewUrlValidator`], which blocks dangerous schemes
/// (`javascript:`, `data:`, `blob:`, `file:`) and enforces optional domain allowlists.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SafeWebViewUrl(String);

impl SafeWebViewUrl {
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

impl fmt::Display for SafeWebViewUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── WebViewUrlValidator ──────────────────────────────────────────────────────

/// Validates URLs for use in WebView contexts.
///
/// Blocks `file://`, `javascript:`, `data:`, `blob:`, and `vbscript:` schemes.
/// Only `http://` and `https://` are allowed. Optionally enforces a domain allowlist.
///
/// # Examples
///
/// ```
/// use secure_boundary::platform::WebViewUrlValidator;
///
/// let validator = WebViewUrlValidator::new();
/// let url = validator.validate("https://example.com/page").unwrap();
/// assert_eq!(url.as_inner(), "https://example.com/page");
/// ```
#[derive(Clone, Debug)]
pub struct WebViewUrlValidator {
    allowed_domains: Option<Vec<String>>,
}

impl WebViewUrlValidator {
    /// Creates a new validator with no domain restrictions (any HTTPS/HTTP domain allowed).
    #[must_use]
    pub fn new() -> Self {
        Self {
            allowed_domains: None,
        }
    }

    /// Adds a domain allowlist. When set, only URLs with matching domains are accepted.
    #[must_use]
    pub fn with_allowed_domains(mut self, domains: &[&str]) -> Self {
        self.allowed_domains = Some(domains.iter().map(|d| d.to_lowercase()).collect());
        self
    }

    /// Validates a URL for WebView use.
    pub fn validate(&self, url: &str) -> Result<SafeWebViewUrl, PlatformRejection> {
        let scheme = extract_scheme(url).ok_or(PlatformRejection::MalformedUrl)?;
        let lower_scheme = scheme.to_lowercase();

        // Block file:// explicitly with specific rejection
        if lower_scheme == "file" {
            return Err(PlatformRejection::FileAccessBlocked);
        }

        // Block dangerous schemes
        if is_dangerous_scheme(scheme) {
            return Err(PlatformRejection::DangerousScheme);
        }

        // Only allow http/https
        if lower_scheme != "http" && lower_scheme != "https" {
            return Err(PlatformRejection::InvalidScheme);
        }

        // Check domain allowlist if configured
        if let Some(ref allowed_domains) = self.allowed_domains {
            let host = extract_host(url).ok_or(PlatformRejection::UntrustedHost)?;
            if !allowed_domains.contains(&host.to_lowercase()) {
                return Err(PlatformRejection::UntrustedHost);
            }
        }

        Ok(SafeWebViewUrl(url.to_owned()))
    }

    /// Validates a URL, returning both the result and any security events emitted.
    pub fn validate_with_events(
        &self,
        url: &str,
    ) -> (
        Result<SafeWebViewUrl, PlatformRejection>,
        Vec<SecurityEvent>,
    ) {
        let result = self.validate(url);
        let events = if result.is_err() {
            vec![make_violation_event()]
        } else {
            vec![]
        };
        (result, events)
    }
}

impl Default for WebViewUrlValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ── ScreenshotPolicy ─────────────────────────────────────────────────────────

/// Screenshot prevention signal for mobile screens.
///
/// This is a policy object — the consuming mobile app is responsible for
/// enforcing it (e.g., `FLAG_SECURE` on Android, screenshot prevention API on iOS).
///
/// # Examples
///
/// ```
/// use secure_boundary::platform::ScreenshotPolicy;
/// use security_core::classification::DataClassification;
///
/// let policy = ScreenshotPolicy::for_classification(DataClassification::Confidential);
/// assert!(policy.should_prevent_screenshot());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenshotPolicy {
    prevent: bool,
}

impl ScreenshotPolicy {
    /// Creates a policy that prevents screenshots.
    #[must_use]
    pub fn prevent() -> Self {
        Self { prevent: true }
    }

    /// Creates a policy that allows screenshots.
    #[must_use]
    pub fn allow() -> Self {
        Self { prevent: false }
    }

    /// Infers screenshot policy from data classification.
    ///
    /// - `Public` / `Internal`: allow screenshots
    /// - `Confidential` and above: prevent screenshots
    #[must_use]
    pub fn for_classification(class: DataClassification) -> Self {
        match class {
            DataClassification::Public | DataClassification::Internal => Self::allow(),
            _ => Self::prevent(),
        }
    }

    /// Returns `true` if screenshots should be prevented on this screen.
    #[must_use]
    pub fn should_prevent_screenshot(&self) -> bool {
        self.prevent
    }
}

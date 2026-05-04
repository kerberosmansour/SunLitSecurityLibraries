//! Cleartext traffic detection — URL scheme and port checks.

use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;

/// The result of cleartext traffic detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleartextResult {
    /// The URL uses an encrypted scheme (e.g., HTTPS).
    Secure,
    /// Cleartext traffic was blocked.
    CleartextBlocked,
    /// The URL was exempted because it targets localhost.
    ExemptedLocalhost,
    /// An insecure non-HTTP scheme was detected (e.g., FTP, telnet).
    InsecureScheme {
        /// The insecure scheme.
        scheme: String,
    },
}

/// Detects cleartext (unencrypted) traffic based on URL analysis.
#[derive(Clone, Debug)]
pub struct CleartextDetector {
    exempt_localhost: bool,
}

impl CleartextDetector {
    /// Creates a new detector with default settings (localhost NOT exempted).
    #[must_use]
    pub fn new() -> Self {
        Self {
            exempt_localhost: false,
        }
    }

    /// Enables localhost exemption (allows `http://127.0.0.1`, `http://localhost`, `http://[::1]`).
    #[must_use]
    pub fn with_localhost_exemption(mut self, exempt: bool) -> Self {
        self.exempt_localhost = exempt;
        self
    }

    /// Checks whether the given URL uses cleartext transport.
    pub fn check(&self, url: &str) -> CleartextResult {
        let lower = url.to_ascii_lowercase();

        let (scheme, rest) = match lower.split_once("://") {
            Some((s, r)) => (s, r),
            None => return CleartextResult::CleartextBlocked,
        };

        match scheme {
            "https" | "wss" => CleartextResult::Secure,
            "http" | "ws" => {
                if self.exempt_localhost && Self::is_localhost(rest) {
                    CleartextResult::ExemptedLocalhost
                } else {
                    CleartextResult::CleartextBlocked
                }
            }
            "ftp" | "telnet" | "gopher" => CleartextResult::InsecureScheme {
                scheme: scheme.to_string(),
            },
            _ => {
                if Self::is_known_secure_scheme(scheme) {
                    CleartextResult::Secure
                } else {
                    CleartextResult::InsecureScheme {
                        scheme: scheme.to_string(),
                    }
                }
            }
        }
    }

    /// Checks and emits a security event on violation.
    pub fn check_and_emit(&self, url: &str, sink: &dyn SecuritySink) -> CleartextResult {
        let result = self.check(url);
        match &result {
            CleartextResult::CleartextBlocked => {
                let mut event = SecurityEvent::new(
                    EventKind::CleartextBlocked,
                    SecuritySeverity::High,
                    EventOutcome::Blocked,
                );
                event.reason_code = Some("cleartext_http");
                sink.write_event(&event);
            }
            CleartextResult::InsecureScheme { .. } => {
                let mut event = SecurityEvent::new(
                    EventKind::CleartextBlocked,
                    SecuritySeverity::High,
                    EventOutcome::Blocked,
                );
                event.reason_code = Some("insecure_scheme");
                sink.write_event(&event);
            }
            CleartextResult::Secure | CleartextResult::ExemptedLocalhost => {}
        }
        result
    }

    fn is_localhost(host_and_path: &str) -> bool {
        let host_port = host_and_path.split('/').next().unwrap_or("");

        // Handle bracketed IPv6 like [::1]:port
        let host = if host_port.starts_with('[') {
            host_port.split(']').next().map(|s| &s[1..]).unwrap_or("")
        } else {
            // For IPv4/hostname, strip port after last colon
            host_port.rsplit_once(':').map_or(host_port, |(h, _)| h)
        };

        matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0")
    }

    fn is_known_secure_scheme(scheme: &str) -> bool {
        matches!(scheme, "https" | "wss" | "ftps" | "ssh" | "sftp")
    }
}

impl Default for CleartextDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_detection() {
        assert!(CleartextDetector::is_localhost("localhost/path"));
        assert!(CleartextDetector::is_localhost("127.0.0.1:8080/path"));
        assert!(CleartextDetector::is_localhost("[::1]:443/path"));
        assert!(!CleartextDetector::is_localhost("example.com/path"));
    }
}

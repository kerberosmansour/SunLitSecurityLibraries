//! Mobile-specific log sanitization for MASVS-STORAGE-2 and MASVS-CODE-2.
//!
//! Provides:
//! - [`MobileRedactionEngine`] — scrubs device identifiers (IMEI, IDFV, GAID/IDFA,
//!   MAC addresses) and GPS coordinates from [`SecurityEvent`] labels.
//! - [`LogLevelEnforcer`] — compile-time log level enforcement that suppresses
//!   debug/trace events in release builds.
//! - [`LogLevel`] — log verbosity levels for event filtering.
//!
//! Integrates with the existing [`RedactionEngine`](crate::redact::RedactionEngine)
//! pipeline: mobile scrubbing runs *before* classification-driven redaction.

use crate::event::{EventValue, SecurityEvent};
use std::collections::BTreeMap;

/// Log verbosity levels for [`LogLevelEnforcer`].
///
/// Ordered from most verbose (`Trace`) to least verbose (`Error`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Most verbose — fine-grained tracing.
    Trace = 0,
    /// Debug-level diagnostic output.
    Debug = 1,
    /// Informational messages.
    Info = 2,
    /// Warnings that may need attention.
    Warn = 3,
    /// Errors requiring action.
    Error = 4,
}

/// Enforces a minimum log level, suppressing events below the threshold.
///
/// Use [`LogLevelEnforcer::release()`] for production builds (strips `Trace` and
/// `Debug`) and [`LogLevelEnforcer::debug()`] for development (allows all levels).
#[derive(Clone, Debug)]
pub struct LogLevelEnforcer {
    min_level: LogLevel,
}

impl LogLevelEnforcer {
    /// Creates an enforcer for release builds — suppresses `Trace` and `Debug`.
    #[must_use]
    pub fn release() -> Self {
        Self {
            min_level: LogLevel::Info,
        }
    }

    /// Creates an enforcer for debug builds — allows all log levels.
    #[must_use]
    pub fn debug() -> Self {
        Self {
            min_level: LogLevel::Trace,
        }
    }

    /// Creates an enforcer with a custom minimum log level.
    #[must_use]
    pub fn with_min_level(min_level: LogLevel) -> Self {
        Self { min_level }
    }

    /// Returns `true` if the given log level should be emitted (i.e. it is
    /// at or above the configured minimum).
    #[must_use]
    pub fn should_emit(&self, level: LogLevel) -> bool {
        level >= self.min_level
    }
}

/// Keys whose UUID values should NOT be treated as device/advertising IDs.
const NON_DEVICE_UUID_KEYS: &[&str] = &[
    "event_id",
    "parent_event_id",
    "request_id",
    "trace_id",
    "correlation_id",
    "session_id",
    "transaction_id",
    "span_id",
];

/// Scrubs mobile-specific device identifiers and location data from
/// [`SecurityEvent`] labels.
///
/// Pattern matching order:
/// 1. IMEI — exactly 15 digits
/// 2. MAC address — `XX:XX:XX:XX:XX:XX` or `XX-XX-XX-XX-XX-XX`
/// 3. GPS coordinates — decimal latitude/longitude pair
/// 4. UUID-format device IDs (IDFV, GAID, IDFA) — only when the label key
///    suggests a device or advertising identifier
#[derive(Clone, Debug)]
pub struct MobileRedactionEngine {
    _private: (),
}

impl MobileRedactionEngine {
    /// Creates a new [`MobileRedactionEngine`] with default patterns.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Processes a [`SecurityEvent`], scrubbing mobile device identifiers and
    /// location coordinates from label values.
    #[must_use]
    pub fn scrub_event(&self, mut event: SecurityEvent) -> SecurityEvent {
        let mut new_labels = BTreeMap::new();
        for (key, value) in event.labels {
            match value {
                EventValue::Classified {
                    value: v,
                    classification,
                } => {
                    let scrubbed = self.scrub_value(&key, &v);
                    new_labels.insert(
                        key,
                        EventValue::Classified {
                            value: scrubbed,
                            classification,
                        },
                    );
                }
            }
        }
        event.labels = new_labels;
        event
    }

    /// Scrubs a single value, returning the replacement string.
    fn scrub_value(&self, key: &str, value: &str) -> String {
        let trimmed = value.trim();

        // 1. Check for IMEI (exactly 15 digits)
        if is_imei(trimmed) {
            return "[DEVICE_ID_REDACTED]".to_string();
        }

        // 2. Check for MAC address
        if is_mac_address(trimmed) {
            return "[DEVICE_ID_REDACTED]".to_string();
        }

        // 3. Check for GPS coordinates
        if is_gps_coordinates(trimmed) {
            return "[LOCATION_REDACTED]".to_string();
        }

        // 4. Check for UUID-format device/advertising IDs
        if is_uuid(trimmed) && is_device_id_key(key) {
            return if is_advertising_id_key(key) {
                "[AD_ID_REDACTED]".to_string()
            } else {
                "[DEVICE_ID_REDACTED]".to_string()
            };
        }

        value.to_string()
    }
}

impl Default for MobileRedactionEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` if the string is exactly 15 ASCII digits (IMEI format).
fn is_imei(s: &str) -> bool {
    s.len() == 15 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Returns `true` if the string matches MAC address format:
/// `XX:XX:XX:XX:XX:XX` or `XX-XX-XX-XX-XX-XX` where X is a hex digit.
fn is_mac_address(s: &str) -> bool {
    if s.len() != 17 {
        return false;
    }
    let bytes = s.as_bytes();
    let separator = bytes[2];
    if separator != b':' && separator != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        let pos_in_group = i % 3;
        if pos_in_group == 2 {
            if i == 17 - 1 {
                // Last char should be hex
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            } else if b != separator {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Returns `true` if the string looks like a GPS coordinate pair:
/// `[-]DD.DDDD, [-]DDD.DDDD` (latitude, longitude with decimal points).
fn is_gps_coordinates(s: &str) -> bool {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return false;
    }
    is_decimal_coordinate(parts[0].trim()) && is_decimal_coordinate(parts[1].trim())
}

/// Returns `true` if the string is a decimal number with a fractional part,
/// optionally prefixed with `-`.
fn is_decimal_coordinate(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    let dot_parts: Vec<&str> = s.split('.').collect();
    if dot_parts.len() != 2 {
        return false;
    }
    let integer = dot_parts[0];
    let fraction = dot_parts[1];
    if integer.is_empty() || fraction.is_empty() {
        return false;
    }
    // Latitude integer part: 1-3 digits; fraction: at least 1 digit
    if integer.len() > 3 || integer.is_empty() {
        return false;
    }
    integer.bytes().all(|b| b.is_ascii_digit()) && fraction.bytes().all(|b| b.is_ascii_digit())
}

/// Returns `true` if the string is a standard UUID format:
/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (case-insensitive).
fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    // Hyphens at positions 8, 13, 18, 23
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Returns `true` if the label key suggests a device identifier.
fn is_device_id_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    // Exclude keys that are clearly non-device IDs
    if NON_DEVICE_UUID_KEYS.iter().any(|&k| lower == k) {
        return false;
    }
    lower.contains("idfv")
        || lower.contains("idfa")
        || lower.contains("gaid")
        || lower.contains("ad_id")
        || lower.contains("advertising")
        || lower.contains("device")
        || lower.contains("vendor")
        || lower.contains("hardware")
}

/// Returns `true` if the label key suggests an advertising identifier.
fn is_advertising_id_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("ad_id")
        || lower.contains("idfa")
        || lower.contains("gaid")
        || lower.contains("advertising")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_imei() {
        assert!(is_imei("353456789012345"));
        assert!(!is_imei("12345678901234")); // 14 digits
        assert!(!is_imei("1234567890123456")); // 16 digits
        assert!(!is_imei("35345678901234a")); // non-digit
    }

    #[test]
    fn test_is_mac_address() {
        assert!(is_mac_address("AA:BB:CC:DD:EE:FF"));
        assert!(is_mac_address("aa:bb:cc:dd:ee:ff"));
        assert!(is_mac_address("AA-BB-CC-DD-EE-FF"));
        assert!(!is_mac_address("AA:BB:CC:DD:EE")); // too short
        assert!(!is_mac_address("AABBCCDDEEFF")); // no separators
        assert!(!is_mac_address("GG:BB:CC:DD:EE:FF")); // invalid hex
    }

    #[test]
    fn test_is_gps_coordinates() {
        assert!(is_gps_coordinates("37.7749, -122.4194"));
        assert!(is_gps_coordinates("-33.8688, 151.2093"));
        assert!(is_gps_coordinates("0.0, 0.0"));
        assert!(!is_gps_coordinates("hello, world"));
        assert!(!is_gps_coordinates("37.7749"));
        assert!(!is_gps_coordinates(""));
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("E621E1F8-C36C-495A-93FC-0C247A3E6E5F"));
        assert!(is_uuid("38400000-8cf0-11bd-b23e-10b96e40000d"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("E621E1F8C36C495A93FC0C247A3E6E5F")); // no hyphens
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
        assert!(LogLevel::Debug > LogLevel::Trace);
    }
}

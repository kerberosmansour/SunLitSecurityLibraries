//! Data retention policy enforcement.
//!
//! Provides retention period validation and expiry signaling. Retention policies
//! signal intent for data lifecycle management — they do not delete data themselves.

use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;
use serde::Serialize;
use time::Duration;
use time::OffsetDateTime;

/// The retention status of a data record.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum RetentionStatus {
    /// Data is within its retention period.
    Active,
    /// Data has exceeded its retention period and should be deleted.
    Expired,
    /// No retention policy is defined for this data (warning state).
    NoPolicy,
}

/// A data retention policy specifying how long data should be kept.
pub struct RetentionPolicy {
    retention_days: u64,
    label: String,
}

impl RetentionPolicy {
    /// Creates a new retention policy with the given number of days.
    #[must_use]
    pub fn new(retention_days: u64, label: &str) -> Self {
        Self {
            retention_days,
            label: label.to_string(),
        }
    }

    /// Returns the retention period in days.
    #[must_use]
    pub fn retention_days(&self) -> u64 {
        self.retention_days
    }

    /// Checks the retention status of data created at `created_at`, evaluated at `now`.
    ///
    /// If the data has expired, emits a `RetentionExpiry` security event to the sink.
    pub fn check_status(
        &self,
        created_at: OffsetDateTime,
        now: OffsetDateTime,
        sink: &dyn SecuritySink,
    ) -> RetentionStatus {
        let age = now - created_at;
        let limit = Duration::days(self.retention_days as i64);

        if age > limit {
            let mut event = SecurityEvent::new(
                EventKind::RetentionExpiry,
                SecuritySeverity::Medium,
                EventOutcome::Failure,
            );
            event.labels.insert(
                "policy_label".to_string(),
                EventValue::Classified {
                    value: self.label.clone(),
                    classification: DataClassification::Internal,
                },
            );
            event.labels.insert(
                "retention_days".to_string(),
                EventValue::Classified {
                    value: self.retention_days.to_string(),
                    classification: DataClassification::Internal,
                },
            );
            event.labels.insert(
                "data_age_days".to_string(),
                EventValue::Classified {
                    value: age.whole_days().to_string(),
                    classification: DataClassification::Internal,
                },
            );
            sink.write_event(&event);
            RetentionStatus::Expired
        } else {
            RetentionStatus::Active
        }
    }
}

/// Checks retention status when no policy is defined. Returns `RetentionStatus::NoPolicy`.
#[must_use]
pub fn check_no_policy() -> RetentionStatus {
    RetentionStatus::NoPolicy
}

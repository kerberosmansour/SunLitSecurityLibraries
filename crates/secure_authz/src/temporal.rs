//! Time-bounded permission helpers.
//!
//! The [`PermissionWindow`] type stores validity windows in subject or resource
//! attributes so authorization checks can deny expired or not-yet-active access.
use std::collections::BTreeMap;

use thiserror::Error;
use time::OffsetDateTime;

use crate::{resource::ResourceRef, subject::Subject};

/// Subject/resource attribute key storing the earliest valid time as a Unix timestamp.
pub const VALID_FROM_ATTR: &str = "authz_valid_from";
/// Subject/resource attribute key storing the latest valid time as a Unix timestamp.
pub const VALID_UNTIL_ATTR: &str = "authz_valid_until";

/// Errors raised while decoding time-bounded permission metadata.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemporalError {
    /// A stored timestamp could not be parsed as a valid Unix timestamp.
    #[error("invalid permission timestamp for {field}: {value}")]
    InvalidTimestamp {
        /// The failing attribute name.
        field: &'static str,
        /// The untrusted attribute value.
        value: String,
    },
}

/// A time window that controls when an authorization decision is valid.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionWindow {
    /// Optional opening time. If absent, access is valid immediately.
    pub valid_from: Option<OffsetDateTime>,
    /// Optional closing time. If absent, access does not expire.
    pub valid_until: Option<OffsetDateTime>,
}

impl PermissionWindow {
    /// Creates an unconstrained window.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::temporal::PermissionWindow;
    ///
    /// let window = PermissionWindow::new();
    /// assert!(window.valid_from.is_none());
    /// assert!(window.valid_until.is_none());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the earliest time when the permission becomes active.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::temporal::PermissionWindow;
    /// use time::{Duration, OffsetDateTime};
    ///
    /// let now = OffsetDateTime::now_utc();
    /// let window = PermissionWindow::new().starting_at(now - Duration::minutes(5));
    /// assert!(window.is_active_at(now));
    /// ```
    pub fn starting_at(mut self, valid_from: OffsetDateTime) -> Self {
        self.valid_from = Some(valid_from);
        self
    }

    /// Sets the latest time when the permission remains valid.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::temporal::PermissionWindow;
    /// use time::{Duration, OffsetDateTime};
    ///
    /// let now = OffsetDateTime::now_utc();
    /// let window = PermissionWindow::new().expiring_at(now + Duration::minutes(5));
    /// assert!(window.is_active_at(now));
    /// ```
    pub fn expiring_at(mut self, valid_until: OffsetDateTime) -> Self {
        self.valid_until = Some(valid_until);
        self
    }

    /// Returns `true` when the window is active at `now`.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::temporal::PermissionWindow;
    /// use time::{Duration, OffsetDateTime};
    ///
    /// let now = OffsetDateTime::now_utc();
    /// let window = PermissionWindow::new()
    ///     .starting_at(now - Duration::minutes(1))
    ///     .expiring_at(now + Duration::minutes(1));
    ///
    /// assert!(window.is_active_at(now));
    /// ```
    #[must_use]
    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        if let Some(valid_from) = self.valid_from {
            if now < valid_from {
                return false;
            }
        }

        if let Some(valid_until) = self.valid_until {
            if now > valid_until {
                return false;
            }
        }

        true
    }

    /// Applies this permission window to a [`Subject`]'s attributes.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::{temporal::PermissionWindow, testkit::test_subject};
    /// use time::OffsetDateTime;
    ///
    /// let mut subject = test_subject("alice", &[]);
    /// PermissionWindow::new()
    ///     .starting_at(OffsetDateTime::now_utc())
    ///     .apply_to_subject(&mut subject)
    ///     .unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error only if a stored timestamp cannot be represented safely.
    pub fn apply_to_subject(&self, subject: &mut Subject) -> Result<(), TemporalError> {
        Self::write_attributes(&mut subject.attributes, self);
        Ok(())
    }

    /// Applies this permission window to a [`ResourceRef`]'s attributes.
    ///
    /// # Errors
    ///
    /// Returns an error only if a stored timestamp cannot be represented safely.
    pub fn apply_to_resource(&self, resource: &mut ResourceRef) -> Result<(), TemporalError> {
        Self::write_attributes(&mut resource.attributes, self);
        Ok(())
    }

    /// Decodes a permission window from the provided attributes.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_authz::{temporal::PermissionWindow, testkit::test_subject};
    /// use time::{Duration, OffsetDateTime};
    ///
    /// let now = OffsetDateTime::now_utc();
    /// let mut subject = test_subject("alice", &[]);
    /// let expected = PermissionWindow::new().expiring_at(now + Duration::minutes(5));
    /// expected.apply_to_subject(&mut subject).unwrap();
    ///
    /// let decoded = PermissionWindow::from_attributes(&subject.attributes).unwrap();
    /// let decoded = decoded.unwrap();
    /// assert_eq!(
    ///     decoded.valid_until.unwrap().unix_timestamp(),
    ///     expected.valid_until.unwrap().unix_timestamp(),
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TemporalError::InvalidTimestamp`] when an attribute is present but malformed.
    pub fn from_attributes(
        attributes: &BTreeMap<String, String>,
    ) -> Result<Option<Self>, TemporalError> {
        if !Self::has_constraints(attributes) {
            return Ok(None);
        }

        let valid_from = Self::parse_timestamp(attributes, VALID_FROM_ATTR)?;
        let valid_until = Self::parse_timestamp(attributes, VALID_UNTIL_ATTR)?;
        Ok(Some(Self {
            valid_from,
            valid_until,
        }))
    }

    /// Returns `true` when the attributes contain temporal constraints.
    #[must_use]
    pub fn has_constraints(attributes: &BTreeMap<String, String>) -> bool {
        attributes.contains_key(VALID_FROM_ATTR) || attributes.contains_key(VALID_UNTIL_ATTR)
    }

    fn write_attributes(attributes: &mut BTreeMap<String, String>, window: &Self) {
        match window.valid_from {
            Some(valid_from) => {
                attributes.insert(
                    VALID_FROM_ATTR.to_string(),
                    valid_from.unix_timestamp().to_string(),
                );
            }
            None => {
                attributes.remove(VALID_FROM_ATTR);
            }
        }

        match window.valid_until {
            Some(valid_until) => {
                attributes.insert(
                    VALID_UNTIL_ATTR.to_string(),
                    valid_until.unix_timestamp().to_string(),
                );
            }
            None => {
                attributes.remove(VALID_UNTIL_ATTR);
            }
        }
    }

    fn parse_timestamp(
        attributes: &BTreeMap<String, String>,
        field: &'static str,
    ) -> Result<Option<OffsetDateTime>, TemporalError> {
        let Some(value) = attributes.get(field) else {
            return Ok(None);
        };

        let parsed = value
            .parse::<i64>()
            .map_err(|_| TemporalError::InvalidTimestamp {
                field,
                value: value.clone(),
            })?;

        let timestamp = OffsetDateTime::from_unix_timestamp(parsed).map_err(|_| {
            TemporalError::InvalidTimestamp {
                field,
                value: value.clone(),
            }
        })?;

        Ok(Some(timestamp))
    }
}

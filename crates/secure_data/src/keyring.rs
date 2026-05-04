// Key ring — logical key registry with aliases, versions, and activation windows.

use std::collections::HashMap;

use crate::error::DataError;

/// The lifecycle status of a key version.
///
/// # Examples
///
/// ```
/// use secure_data::keyring::KeyVersionStatus;
///
/// let status = KeyVersionStatus::Active;
/// assert_eq!(status, KeyVersionStatus::Active);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyVersionStatus {
    /// The version is active and may be used for encryption and decryption.
    Active,
    /// The version may only be used for decryption (rotation in progress).
    DecryptOnly,
    /// The version has been deactivated and cannot be used for any operation.
    Deactivated,
}

/// Metadata for a single key version.
///
/// # Examples
///
/// ```
/// use secure_data::keyring::{KeyVersionEntry, KeyVersionStatus};
///
/// let entry = KeyVersionEntry {
///     version_id: "v1".to_string(),
///     status: KeyVersionStatus::Active,
/// };
/// assert_eq!(entry.version_id, "v1");
/// ```
#[derive(Debug, Clone)]
pub struct KeyVersionEntry {
    /// The version identifier (e.g. "v1", "v2").
    pub version_id: String,
    /// Current lifecycle status.
    pub status: KeyVersionStatus,
}

/// An entry in the key ring for a named key alias.
#[derive(Debug, Default)]
struct KeyEntry {
    versions: Vec<KeyVersionEntry>,
    /// Counter used to generate the next version id.
    next_version_counter: u32,
}

impl KeyEntry {
    fn active_version(&self) -> Option<&KeyVersionEntry> {
        self.versions
            .iter()
            .find(|v| v.status == KeyVersionStatus::Active)
    }

    fn usable_count(&self) -> usize {
        self.versions
            .iter()
            .filter(|v| {
                v.status == KeyVersionStatus::Active || v.status == KeyVersionStatus::DecryptOnly
            })
            .count()
    }
}

/// A logical registry of key aliases and their versioned lifecycle.
///
/// # Examples
///
/// ```
/// use secure_data::keyring::{KeyRing, KeyVersionStatus};
///
/// let mut ring = KeyRing::new();
/// ring.add_key("db-key".to_string(), "v1".to_string());
/// assert_eq!(ring.active_version("db-key"), Some("v1"));
///
/// let v2 = ring.rotate("db-key").unwrap();
/// assert_eq!(ring.active_version("db-key"), Some(v2.as_str()));
/// assert_eq!(ring.version_status("db-key", "v1"), Some(KeyVersionStatus::DecryptOnly));
/// ```
#[derive(Debug, Default)]
pub struct KeyRing {
    entries: HashMap<String, KeyEntry>,
}

impl KeyRing {
    /// Creates an empty `KeyRing`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a key alias with an initial version in `Active` status.
    pub fn add_key(&mut self, alias: String, initial_version: String) {
        let entry = self.entries.entry(alias).or_default();
        entry.versions.push(KeyVersionEntry {
            version_id: initial_version,
            status: KeyVersionStatus::Active,
        });
        entry.next_version_counter += 1;
    }

    /// Rotates a key: marks the current `Active` version as `DecryptOnly` and creates
    /// a new `Active` version.
    ///
    /// # Errors
    /// Returns [`DataError::UnknownAlias`] if the alias is not registered.
    pub fn rotate(&mut self, alias: &str) -> Result<String, DataError> {
        let entry = self
            .entries
            .get_mut(alias)
            .ok_or_else(|| DataError::UnknownAlias {
                alias: alias.to_string(),
            })?;

        // Demote current active → DecryptOnly
        for v in entry.versions.iter_mut() {
            if v.status == KeyVersionStatus::Active {
                v.status = KeyVersionStatus::DecryptOnly;
            }
        }

        // Create new active version
        entry.next_version_counter += 1;
        let new_version_id = format!("v{}", entry.next_version_counter);
        entry.versions.push(KeyVersionEntry {
            version_id: new_version_id.clone(),
            status: KeyVersionStatus::Active,
        });

        Ok(new_version_id)
    }

    /// Deactivates a specific key version.
    ///
    /// # Errors
    /// - [`DataError::UnknownAlias`] if the alias is not registered.
    /// - [`DataError::CannotDeactivateLastVersion`] if this would leave zero usable versions.
    pub fn deactivate(&mut self, alias: &str, version_id: &str) -> Result<(), DataError> {
        let entry = self
            .entries
            .get_mut(alias)
            .ok_or_else(|| DataError::UnknownAlias {
                alias: alias.to_string(),
            })?;

        // Check we have more than one usable version
        if entry.usable_count() <= 1 {
            return Err(DataError::CannotDeactivateLastVersion {
                alias: alias.to_string(),
            });
        }

        for v in entry.versions.iter_mut() {
            if v.version_id == version_id {
                v.status = KeyVersionStatus::Deactivated;
                return Ok(());
            }
        }

        Err(DataError::KeyVersionUnavailable {
            alias: alias.to_string(),
            version: version_id.to_string(),
        })
    }

    /// Returns the status of a specific version.
    ///
    /// # Errors
    /// Returns `None` if the alias or version does not exist.
    pub fn version_status(&self, alias: &str, version_id: &str) -> Option<KeyVersionStatus> {
        let entry = self.entries.get(alias)?;
        entry
            .versions
            .iter()
            .find(|v| v.version_id == version_id)
            .map(|v| v.status.clone())
    }

    /// Returns the currently active version id for an alias.
    pub fn active_version(&self, alias: &str) -> Option<&str> {
        self.entries
            .get(alias)
            .and_then(|e| e.active_version())
            .map(|v| v.version_id.as_str())
    }
}

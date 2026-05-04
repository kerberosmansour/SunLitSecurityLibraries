//! Example DTOs with `SecureValidate` and `deny_unknown_fields`.
//!
//! These DTOs demonstrate how to wire secure validation into deserialization.

use secure_boundary::validate::{SecureValidate, ValidationContext};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request body for creating a new item.
///
/// `deny_unknown_fields` ensures extra fields are rejected at the boundary.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateItemRequest {
    /// The item name. Must be 1–100 characters.
    pub name: String,
    /// Optional description (max 500 characters).
    #[serde(default)]
    pub description: Option<String>,
}

impl SecureValidate for CreateItemRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.name.is_empty() {
            return Err("name_empty");
        }
        if self.name.len() > 100 {
            return Err("name_too_long");
        }
        if let Some(desc) = &self.description {
            if desc.len() > 500 {
                return Err("description_too_long");
            }
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Request body for updating an existing item.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateItemRequest {
    /// The updated name. Must be 1–100 characters.
    pub name: String,
    /// Optional updated description.
    #[serde(default)]
    pub description: Option<String>,
}

impl SecureValidate for UpdateItemRequest {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.name.is_empty() {
            return Err("name_empty");
        }
        if self.name.len() > 100 {
            return Err("name_too_long");
        }
        if let Some(desc) = &self.description {
            if desc.len() > 500 {
                return Err("description_too_long");
            }
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Response body for an item resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResponse {
    /// The unique item identifier.
    pub id: Uuid,
    /// The item name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The owner's actor identifier.
    pub owner_id: String,
    /// The tenant identifier.
    pub tenant_id: Option<String>,
}

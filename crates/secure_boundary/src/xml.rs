//! `SecureXml<T>` — axum extractor with XXE prevention.
//!
//! Parses XML request bodies with the following security controls:
//! - DOCTYPE declarations (including entity definitions) are blocked entirely.
//! - Body size is bounded by [`RequestLimits::max_body_bytes`].
//! - Accepts `application/xml` and `text/xml` content types.
//!
//! Gated on the `axum` feature — an actix-web 4 `SecureXml` adapter may be
//! added in a future runbook (not in Gate A scope).

#![cfg(feature = "axum")]

use axum::extract::{FromRequest, Request};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;

use crate::{
    attack_signal::{BoundaryViolation, ViolationKind},
    error::BoundaryRejection,
    limits::RequestLimits,
    validate::{SecureValidate, ValidationContext},
};

/// An XML body extractor that prevents XXE and enforces body size limits.
///
/// Use `.into_inner()` to consume the validated inner value.
/// `Deref<Target=T>` is not implemented by design.
pub struct SecureXml<T>(pub T);

impl<T> SecureXml<T> {
    /// Consumes the extractor and returns the validated inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T, S> FromRequest<S> for SecureXml<T>
where
    T: DeserializeOwned + SecureValidate,
    S: Send + Sync,
{
    type Rejection = BoundaryRejection;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let limits = RequestLimits::default();
        let ctx = ValidationContext::new();

        // Stage 1: Content-Type check (application/xml or text/xml)
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.starts_with("application/xml") && !content_type.starts_with("text/xml") {
            BoundaryViolation::new(ViolationKind::InvalidContentType, "invalid_content_type")
                .emit();
            return Err(BoundaryRejection::InvalidContentType);
        }

        // Collect body bytes
        let bytes = req
            .into_body()
            .collect()
            .await
            .map_err(|_| BoundaryRejection::MalformedBody)?
            .to_bytes();

        // Stage 1 (cont): Body size limit
        if bytes.len() > limits.max_body_bytes {
            BoundaryViolation::new(ViolationKind::BodyTooLarge, "body_too_large").emit();
            return Err(BoundaryRejection::BodyTooLarge);
        }

        // Convert to UTF-8 string for processing
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            BoundaryViolation::new(ViolationKind::SyntaxViolation, "invalid_utf8").emit();
            BoundaryRejection::MalformedBody
        })?;

        // Stage 2: XXE prevention — scan for DOCTYPE declarations
        check_for_xxe(text)?;

        // Stage 3: Deserialise with quick-xml
        let value: T = quick_xml::de::from_str(text).map_err(|_| {
            BoundaryViolation::new(ViolationKind::SyntaxViolation, "malformed_xml").emit();
            BoundaryRejection::MalformedBody
        })?;

        // Stage 4: Semantic validation
        value.validate_syntax(&ctx).map_err(|code| {
            BoundaryViolation::new(ViolationKind::SyntaxViolation, code).emit();
            BoundaryRejection::SyntaxViolation { code }
        })?;

        value.validate_semantics(&ctx).map_err(|code| {
            BoundaryViolation::new(ViolationKind::SemanticViolation, code).emit();
            BoundaryRejection::SemanticViolation { code }
        })?;

        Ok(Self(value))
    }
}

/// Scans XML text for DOCTYPE declarations (DTD + entity definitions).
///
/// Any occurrence of `<!DOCTYPE` or `<!ENTITY` (case-insensitive) causes
/// immediate rejection to prevent XXE and billion-laughs attacks.
fn check_for_xxe(xml: &str) -> Result<(), BoundaryRejection> {
    let upper = xml.to_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        BoundaryViolation::new(ViolationKind::SyntaxViolation, "xxe_blocked").emit();
        return Err(BoundaryRejection::XxeBlocked);
    }
    Ok(())
}

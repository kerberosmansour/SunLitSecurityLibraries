//! Boundary rejection error type with safe HTTP response mapping.

use http::StatusCode;
use thiserror::Error;

/// Errors that may occur when processing a request at the security boundary.
///
/// All variants map to safe HTTP responses. No raw input is ever echoed in the
/// response body — only stable, machine-readable codes are returned.
///
/// This enum is `#[non_exhaustive]` — new variants may be added in future minor versions.
///
/// # Examples
///
/// ```
/// use secure_boundary::error::BoundaryRejection;
///
/// let err = BoundaryRejection::BodyTooLarge;
/// assert_eq!(err.to_string(), "request body too large");
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Error)]
pub enum BoundaryRejection {
    /// The request body exceeded the configured size limit.
    #[error("request body too large")]
    BodyTooLarge,

    /// The `Content-Type` header was missing or not in the allowlist.
    #[error("invalid or missing Content-Type")]
    InvalidContentType,

    /// The request body was malformed or contained unknown fields.
    #[error("malformed or unknown-field request body")]
    MalformedBody,

    /// A path or query parameter failed validation.
    #[error("invalid request parameter")]
    InvalidParameter,

    /// Syntactic validation failed.
    #[error("syntactic validation failed")]
    SyntaxViolation {
        /// A stable internal reason code. Never echoed verbatim to clients.
        code: &'static str,
    },

    /// Semantic validation failed.
    #[error("semantic validation failed")]
    SemanticViolation {
        /// A stable internal reason code. Never echoed verbatim to clients.
        code: &'static str,
    },

    /// The JSON body was nested too deeply.
    #[error("request body nesting too deep")]
    NestingTooDeep,

    /// The JSON body contained too many fields.
    #[error("request body has too many fields")]
    TooManyFields,

    /// A path traversal attempt was detected.
    #[error("path traversal detected")]
    PathTraversal,

    /// An injection attempt was detected (command, SQL, LDAP, filename, redirect).
    #[error("injection attempt detected")]
    InjectionAttempt {
        /// A stable internal reason code. Never echoed verbatim to clients.
        code: &'static str,
    },

    /// An SSRF attempt was blocked (dangerous URL or private IP).
    #[error("SSRF attempt blocked")]
    SsrfAttempt,

    /// An XXE attack was blocked (DOCTYPE or entity expansion in XML).
    #[error("XXE attack blocked")]
    XxeBlocked,

    /// A header value contained CRLF injection characters.
    #[error("invalid header value: CRLF detected")]
    InvalidHeaderValue,
}

impl BoundaryRejection {
    /// Returns the HTTP status code appropriate for this rejection.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::InvalidContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::MalformedBody
            | Self::InvalidParameter
            | Self::SyntaxViolation { .. }
            | Self::SemanticViolation { .. }
            | Self::NestingTooDeep
            | Self::TooManyFields
            | Self::PathTraversal
            | Self::InjectionAttempt { .. }
            | Self::SsrfAttempt
            | Self::XxeBlocked
            | Self::InvalidHeaderValue => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    /// Returns a stable, client-safe error code string.
    ///
    /// This code is safe to return in HTTP responses — it contains no raw input.
    #[must_use]
    pub fn client_code(&self) -> &'static str {
        match self {
            Self::BodyTooLarge => "body_too_large",
            Self::InvalidContentType => "invalid_content_type",
            Self::MalformedBody => "malformed_body",
            Self::InvalidParameter => "invalid_parameter",
            Self::SyntaxViolation { .. } => "syntax_violation",
            Self::SemanticViolation { .. } => "semantic_violation",
            Self::NestingTooDeep => "nesting_too_deep",
            Self::TooManyFields => "too_many_fields",
            Self::PathTraversal => "path_traversal",
            Self::InjectionAttempt { .. } => "injection_attempt",
            Self::SsrfAttempt => "ssrf_attempt",
            Self::XxeBlocked => "xxe_blocked",
            Self::InvalidHeaderValue => "invalid_header_value",
        }
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for BoundaryRejection {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let status = self.status_code();
        let code = self.client_code();
        // Only stable codes are returned — never raw input
        let body = format!(r#"{{"error":{{"code":"{}"}}}}"#, code);
        axum::http::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|_| {
                axum::http::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::empty())
                    .expect("static fallback response always builds")
            })
    }
}

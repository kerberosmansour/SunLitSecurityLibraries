//! HTTP body/query/path extractors implementing the four-stage validation pipeline.
//!
//! Stages:
//! 1. **Transport validity** — body size limits, `Content-Type` check
//! 2. **Syntactic validity** — JSON parsing, unknown-field rejection via serde
//! 3. **Semantic validity** — [`SecureValidate`] trait
//! 4. **Authz-adjacent invariants** — future extension point
//!
//! Use `.into_inner()` to consume the validated value. `Deref<Target=T>` is
//! intentionally **not** implemented.
//!
//! The [`SecureJson`], [`SecureQuery`], and [`SecurePath`] new-types are
//! framework-neutral and live here unconditionally. The axum-specific
//! `FromRequest` / `FromRequestParts` implementations are gated on the
//! `axum` feature (default). The matching Actix-web 4 implementation for
//! `SecureJson<T>` lives under the crate's `actix` module (behind the
//! `actix-web` feature).

#[cfg(any(feature = "axum", feature = "actix-web"))]
use serde::de::DeserializeOwned;

#[cfg(any(feature = "axum", feature = "actix-web"))]
use crate::{
    attack_signal::{BoundaryViolation, ViolationKind},
    error::BoundaryRejection,
    limits::RequestLimits,
    validate::{SecureValidate, ValidationContext},
};

/// A JSON body extractor that applies the four-stage validation pipeline.
///
/// Use `.into_inner()` to consume the validated inner value.
/// `Deref<Target=T>` is not implemented by design.
///
/// # Examples
///
/// ```no_run
/// use secure_boundary::extract::SecureJson;
/// use secure_boundary::validate::{SecureValidate, ValidationContext};
///
/// #[derive(serde::Deserialize)]
/// #[serde(deny_unknown_fields)]
/// struct CreateItem {
///     name: String,
/// }
///
/// impl SecureValidate for CreateItem {
///     fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> {
///         if self.name.is_empty() { Err("name_empty") } else { Ok(()) }
///     }
///     fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
/// }
///
/// async fn handler(json: SecureJson<CreateItem>) {
///     let item = json.into_inner();
///     println!("created: {}", item.name);
/// }
/// ```
pub struct SecureJson<T>(T);

impl<T> SecureJson<T> {
    /// Constructs a [`SecureJson`] directly from an already-validated value.
    ///
    /// Primarily useful inside framework adapters after the four-stage
    /// validation pipeline has completed.
    #[cfg(any(feature = "axum", feature = "actix-web"))]
    #[must_use]
    pub(crate) fn from_validated(value: T) -> Self {
        Self(value)
    }

    /// Consumes the extractor and returns the validated inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// A query parameter extractor that applies syntactic and semantic validation.
///
/// Use `.into_inner()` to consume the validated inner value.
///
/// # Examples
///
/// ```no_run
/// use secure_boundary::extract::SecureQuery;
/// use secure_boundary::validate::{SecureValidate, ValidationContext};
///
/// #[derive(serde::Deserialize)]
/// struct Pagination {
///     page: u32,
/// }
///
/// impl SecureValidate for Pagination {
///     fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
///     fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
/// }
///
/// async fn handler(query: SecureQuery<Pagination>) {
///     let pg = query.into_inner();
///     println!("page: {}", pg.page);
/// }
/// ```
pub struct SecureQuery<T>(T);

impl<T> SecureQuery<T> {
    /// Consumes the extractor and returns the validated inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// A path parameter extractor that applies syntactic and semantic validation.
///
/// Use `.into_inner()` to consume the validated inner value.
///
/// # Examples
///
/// ```no_run
/// use secure_boundary::extract::SecurePath;
/// use secure_boundary::validate::{SecureValidate, ValidationContext};
///
/// #[derive(serde::Deserialize)]
/// struct ItemPath {
///     id: u64,
/// }
///
/// impl SecureValidate for ItemPath {
///     fn validate_syntax(&self, _: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
///     fn validate_semantics(&self, _: &ValidationContext) -> Result<(), &'static str> { Ok(()) }
/// }
///
/// async fn handler(path: SecurePath<ItemPath>) {
///     let p = path.into_inner();
///     println!("item id: {}", p.id);
/// }
/// ```
pub struct SecurePath<T>(T);

impl<T> SecurePath<T> {
    /// Consumes the extractor and returns the validated inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

// Runs the full four-stage JSON validation pipeline against a byte buffer.
//
// Called by every framework-specific `SecureJson<T>` adapter after that
// adapter has (a) confirmed `Content-Type: application/json` and (b)
// collected the request body into bytes. All `BoundaryViolation` emission
// and `BoundaryRejection` mapping happens here so axum and actix-web
// paths agree on outcomes byte-for-byte.
//
// This helper is `pub(crate)` — external consumers use the framework
// extractors.
#[cfg(any(feature = "axum", feature = "actix-web"))]
pub(crate) fn validate_json_bytes<T>(
    bytes: &[u8],
    limits: &RequestLimits,
    ctx: &ValidationContext,
) -> Result<T, BoundaryRejection>
where
    T: DeserializeOwned + SecureValidate,
{
    // Stage 1 (cont): Body size limit
    if bytes.len() > limits.max_body_bytes {
        BoundaryViolation::new(ViolationKind::BodyTooLarge, "body_too_large").emit();
        return Err(BoundaryRejection::BodyTooLarge);
    }

    // Stage 1 (cont): Nesting depth and field count limits
    check_json_limits(bytes, limits.max_nesting_depth, limits.max_field_count)?;

    // Stage 2: Syntactic validity — parse JSON (respects #[serde(deny_unknown_fields)])
    let value: T = serde_json::from_slice(bytes).map_err(|_| {
        BoundaryViolation::new(ViolationKind::SyntaxViolation, "malformed_json").emit();
        BoundaryRejection::MalformedBody
    })?;

    // Stage 3: Semantic validity — SecureValidate trait
    value.validate_syntax(ctx).map_err(|code| {
        BoundaryViolation::new(ViolationKind::SyntaxViolation, code).emit();
        BoundaryRejection::SyntaxViolation { code }
    })?;

    value.validate_semantics(ctx).map_err(|code| {
        BoundaryViolation::new(ViolationKind::SemanticViolation, code).emit();
        BoundaryRejection::SemanticViolation { code }
    })?;

    Ok(value)
}

/// Runs the syntactic+semantic `SecureValidate` pipeline against a value
/// that is already parsed (e.g. via axum's `Query` or `Path` extractor).
///
/// Used by the query/path extractor adapters to keep emission semantics
/// identical between frameworks.
#[cfg(feature = "axum")]
pub(crate) fn validate_parsed<T>(value: T, ctx: &ValidationContext) -> Result<T, BoundaryRejection>
where
    T: SecureValidate,
{
    value.validate_syntax(ctx).map_err(|code| {
        BoundaryViolation::new(ViolationKind::SyntaxViolation, code).emit();
        BoundaryRejection::SyntaxViolation { code }
    })?;

    value.validate_semantics(ctx).map_err(|code| {
        BoundaryViolation::new(ViolationKind::SemanticViolation, code).emit();
        BoundaryRejection::SemanticViolation { code }
    })?;

    Ok(value)
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::{
        validate_json_bytes, validate_parsed, BoundaryRejection, BoundaryViolation,
        DeserializeOwned, RequestLimits, SecurePath, SecureQuery, SecureValidate,
        ValidationContext, ViolationKind,
    };
    use crate::attack_signal;
    use axum::{
        extract::{FromRequest, FromRequestParts, Path, Query, Request},
        http::request::Parts,
    };
    use http_body_util::BodyExt;

    impl<T, S> FromRequest<S> for super::SecureJson<T>
    where
        T: DeserializeOwned + SecureValidate,
        S: Send + Sync,
    {
        type Rejection = BoundaryRejection;

        async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
            // Allow per-route limit overrides via Extension<RequestLimits>.
            let limits = req
                .extensions()
                .get::<RequestLimits>()
                .cloned()
                .unwrap_or_default();
            let ctx = ValidationContext::new();

            // Stage 1: Transport validity — Content-Type check
            let content_type = req
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !content_type.starts_with("application/json") {
                attack_signal::BoundaryViolation::new(
                    attack_signal::ViolationKind::InvalidContentType,
                    "invalid_content_type",
                )
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

            let value = validate_json_bytes::<T>(&bytes, &limits, &ctx)?;
            Ok(super::SecureJson::from_validated(value))
        }
    }

    impl<T, S> FromRequestParts<S> for SecureQuery<T>
    where
        T: DeserializeOwned + SecureValidate,
        S: Send + Sync,
    {
        type Rejection = BoundaryRejection;

        async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
            let ctx = ValidationContext::new();

            let query = Query::<T>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    BoundaryViolation::new(ViolationKind::InvalidQueryParam, "invalid_query")
                        .emit();
                    BoundaryRejection::InvalidParameter
                })?;

            let value = validate_parsed(query.0, &ctx)?;
            Ok(SecureQuery(value))
        }
    }

    impl<T, S> FromRequestParts<S> for SecurePath<T>
    where
        T: DeserializeOwned + SecureValidate + Send,
        S: Send + Sync,
    {
        type Rejection = BoundaryRejection;

        async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
            let ctx = ValidationContext::new();

            let path = Path::<T>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    BoundaryViolation::new(ViolationKind::InvalidPathParam, "invalid_path").emit();
                    BoundaryRejection::InvalidParameter
                })?;

            let value = validate_parsed(path.0, &ctx)?;
            Ok(SecurePath(value))
        }
    }
}

/// Scans raw JSON bytes and enforces nesting depth and field count limits.
///
/// Uses a single-pass byte scanner that correctly skips string contents
/// (handling escape sequences), counting `{`/`[` for depth and `:` for fields.
///
/// # Errors
///
/// Returns [`BoundaryRejection::NestingTooDeep`] or [`BoundaryRejection::TooManyFields`]
/// when the respective limit is exceeded.
#[cfg(any(feature = "axum", feature = "actix-web"))]
fn check_json_limits(
    bytes: &[u8],
    max_depth: usize,
    max_fields: usize,
) -> Result<(), BoundaryRejection> {
    let mut depth: usize = 0;
    let mut field_count: usize = 0;
    let mut in_string = false;
    let mut escape = false;

    for &b in bytes {
        if escape {
            escape = false;
            continue;
        }
        if in_string {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
            }
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    BoundaryViolation::new(ViolationKind::NestingTooDeep, "nesting_too_deep")
                        .emit();
                    return Err(BoundaryRejection::NestingTooDeep);
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            b':' => {
                field_count += 1;
                if field_count > max_fields {
                    BoundaryViolation::new(ViolationKind::TooManyFields, "too_many_fields").emit();
                    return Err(BoundaryRejection::TooManyFields);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

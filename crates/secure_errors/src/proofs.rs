//! Kani proof harnesses for `secure_errors`.
//!
//! Compiled only under `cargo kani` via `#![cfg(kani)]`. See
//! `docs/dev-guide/formal-verification.md` for the proof catalogue and
//! the advisory CI lane (`.github/workflows/kani.yml`).
//!
//! M3 proofs (this file): the public-body-no-leak invariant — for every
//! `AppError` variant, the resulting `PublicError` carries (a) a status
//! code in the standard 4xx/5xx range and (b) a `code` field drawn from
//! a finite set of static literals, never derived from the error's
//! `Display` or `Debug` text.

#![cfg(kani)]

use crate::http::into_response_parts;
use crate::kind::AppError;

/// Proof: every `AppError` variant maps to a status code in the standard
/// 4xx/5xx range, never to a 1xx/2xx/3xx code (which would be a server
/// misconfiguration that surfaces a server error as a success).
#[kani::proof]
fn public_status_code_is_in_4xx_5xx_range() {
    let err: AppError = kani::any();
    let (status, _public) = into_response_parts(&err);

    assert!(status >= 400);
    assert!(status < 600);
}

/// Proof: every `AppError` variant produces a `PublicError` with a
/// non-empty, static `code` field.
///
/// The `code` field is `&'static str` by type — Kani trivially verifies
/// it cannot be derived from the runtime `err.to_string()`. The
/// non-emptiness check guards against a future refactor that returns
/// `""` for a variant.
#[kani::proof]
fn public_error_code_is_non_empty_static_literal() {
    let err: AppError = kani::any();
    let (_status, public) = into_response_parts(&err);

    assert!(!public.code.is_empty());
}

/// Proof: the `code` field for every variant is in the small known set.
///
/// Catches a future copy-paste refactor that introduces a new code
/// without updating this whitelist (and therefore the API contract).
/// When a new `AppError` variant + new `code` is intentionally added,
/// the proof fails and the contributor extends the whitelist
/// deliberately.
#[kani::proof]
fn public_error_code_is_in_whitelist() {
    let err: AppError = kani::any();
    let (_status, public) = into_response_parts(&err);

    let allowed = matches!(
        public.code,
        "invalid_request"
            | "unauthorized"
            | "forbidden"
            | "not_found"
            | "conflict"
            | "temporarily_unavailable"
            | "internal_error"
            | "too_many_requests"
    );
    assert!(allowed);
}

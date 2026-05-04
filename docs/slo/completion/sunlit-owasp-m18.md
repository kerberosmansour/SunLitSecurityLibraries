# Completion Summary — sunlit-owasp Milestone 18

## Goal completed
- `SecureJson<T>` enforces `max_nesting_depth` and `max_field_count` with per-route customisation via `Extension<RequestLimits>`
- HTML sanitization module (`sanitize_html()`, `SanitizeConfig`) added behind `html-sanitize` feature flag

## Files changed
- `crates/secure_boundary/src/extract.rs` — read `Extension<RequestLimits>` with default fallback
- `crates/secure_boundary/src/lib.rs` — added `pub mod sanitize;` under feature gate
- `crates/secure_boundary/Cargo.toml` — added `ammonia` optional dep, `html-sanitize` feature
- `crates/secure_boundary/src/sanitize.rs` — NEW: HTML sanitization module

## Tests added
- `crates/secure_boundary/tests/sunlit_owasp_limits.rs` — 11 BDD tests (depth boundary, field boundary, custom limits, DoS rejection)
- `crates/secure_boundary/tests/sunlit_owasp_sanitize.rs` — 8 BDD tests (XSS, style injection, event handlers, configurable tags)

## Runtime validations added
- `crates/secure_boundary/tests/e2e_sunlit_owasp_m18.rs` — 4 E2E tests (depth, fields, XSS, backward compat)

## Compatibility checks performed
- All existing `SecureJson` tests pass
- All existing `SecureXml` tests pass
- All safe type tests pass
- `SecureValidate` trait unchanged
- `SecurityHeadersLayer` unchanged
- Default limits behaviour identical for payloads within limits

## Documentation updated
- `ARCHITECTURE.md` — added HTML sanitization and custom limits description to `secure_boundary` section
- `README.md` — updated crates table; added HTML sanitization and per-route limit examples
- `docs/dev-guide/secure-boundary.md` — added Extension-based limit config, HTML sanitization section, API reference entries

## .gitignore changes
- None needed — no new generated files or build outputs

## Test artifact cleanup verified
- `git status` shows clean working tree after test run

## Deferred follow-ups
- Property-based test for depth counting edge cases
- Fuzz target for `sanitize_html()` with adversarial input
- Benchmark for `check_json_limits` with large payloads

## Known non-blocking limitations
- Field count uses colon-counting which slightly over-counts for nested objects (safe — errs on rejection side)
- Pre-existing doc warnings in `safe_types.rs` (`Deref`, `as_inner`, `into_inner` unresolved links) — not introduced by M18

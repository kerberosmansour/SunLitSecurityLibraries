# Lessons Learned — sunlit-owasp Milestone 18

## What changed
- `SecureJson<T>` now reads `Extension<RequestLimits>` for per-route limit overrides (falls back to defaults)
- Added `sanitize.rs` module with `sanitize_html()` and `SanitizeConfig` behind `html-sanitize` feature flag
- Added `ammonia` v4.1.2 as an optional dependency

## Design decisions and why
- **Extension-based limit injection** — axum's `Extension<T>` is the idiomatic way to pass per-route configuration without changing the `FromRequest` trait signature or `SecureJson` generics. Falls back to `RequestLimits::default()` when no extension is present, preserving backward compatibility.
- **Free function primary API** (`sanitize_html()`) — follows Kevin Wall's ESAPI principle adapted for Rust: stateless operations get convenience free functions. `SanitizeConfig` exists for when customisation is needed.
- **ammonia over custom implementation** — ammonia is Mozilla-maintained, used by docs.rs, and handles edge cases (nested XSS, data URIs, SVG vectors) that a hand-rolled scanner would miss. Feature-gated to keep default builds lean.
- **Colon-counting for field limits** — the existing `check_json_limits` counts `:` outside strings as a proxy for field count. This slightly over-counts (array elements with colons in string values are handled, but nested objects add colons). The approximation is safe — it errs on the side of rejection.

## Mistakes made
- None significant. The implementation path was straightforward.

## Root causes
- N/A

## What was harder than expected
- The ammonia `Builder::tags()` method requires `HashSet<&str>`, not `&HashSet<String>`, requiring an intermediate conversion.

## Naming conventions established
- Feature flag: `html-sanitize` (kebab-case, descriptive)
- Module: `sanitize.rs` (matches the capability)
- Free function: `sanitize_html()` (verb_noun pattern matching existing `sanitize_header_value()`)
- Config type: `SanitizeConfig` (noun pattern consistent with `RequestLimits`)

## Test patterns that worked well
- Helper functions `make_nested_json(depth)` and `make_field_json(count)` for generating test payloads at precise boundary values
- `post_json()` helper that returns `(StatusCode, String)` for concise assertions on both status and body
- Feature-gated test module (`#[cfg(feature = "html-sanitize")] mod sanitize_tests`) to avoid compilation errors when feature is off

## Missing tests that should exist now
- Property-based test for depth counting (proptest with random nesting)
- Fuzz target for `sanitize_html()` with adversarial input
- Benchmark for `check_json_limits` with large payloads to verify constant-time rejection

## Rules for the next milestone
- When adding new output encoders (M19), follow the same free-function-first API pattern
- The `ammonia` dependency is feature-gated; don't unconditionally import it elsewhere

## Template improvements suggested
- BDD error code names in the runbook should reference actual code values (`nesting_too_deep` not `nesting_depth_exceeded`) to avoid confusion

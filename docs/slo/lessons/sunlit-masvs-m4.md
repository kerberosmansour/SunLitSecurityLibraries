# Lessons Learned — sunlit-masvs Milestone 4

## What changed
- Added `platform` module to `secure_boundary` behind `mobile-platform` feature flag
- Created `SafeDeepLink` (via `DeepLinkValidator`), `ClipboardPolicy`, `SafeWebViewUrl` (via `WebViewUrlValidator`), `ScreenshotPolicy`
- Added `PlatformSafetyViolation` variant to `security_events::EventKind`
- Added `PlatformRejection` error type within the platform module
- 24 BDD tests in `platform_tests.rs`

## Design decisions and why
- **Validator + output type pattern** instead of `TryFrom<&str>`: Deep links and WebView URLs require configuration (allowed schemes, host/domain allowlists). `DeepLinkValidator` and `WebViewUrlValidator` hold config and produce `SafeDeepLink` / `SafeWebViewUrl` output types. This differs from the existing safe types (which use `TryFrom<&str>`) because configurable validation needs state.
- **`PlatformRejection` instead of extending `BoundaryRejection`**: Domain-specific rejection reasons (`InvalidScheme`, `DangerousScheme`, `FileAccessBlocked`, etc.) are distinct from HTTP boundary rejections. Keeping them in the platform module maintains separation of concerns.
- **Single `PlatformSafetyViolation` EventKind**: One variant covers all platform safety violations rather than separate variants per type. The rejection reason provides specificity; the event kind groups them for monitoring dashboards.
- **`ClipboardPolicy::for_classification()`**: Maps `DataClassification` to clipboard restrictions automatically. `Confidential`+ gets local-only; `Secret`/`Credentials` get 60-second expiration. Uses `#[non_exhaustive]` wildcard arm for future classification variants.
- **`ScreenshotPolicy::for_classification()`**: Defaults to prevent for `Confidential` and above, allow for `Public`/`Internal`. Simple boolean policy — the consuming app handles platform-level enforcement.
- **Feature-gated behind `mobile-platform`**: Follows M2/M3 pattern. No weight added for non-mobile consumers.

## Mistakes made
- None significant — applied M3 lessons about feature gating, `SecurityEvent::new()` constructor, and wildcard arms from the start.

## Root causes
- N/A

## What was harder than expected
- Nothing — the existing safe types pattern and M3 validator patterns provided clear guidance.

## Naming conventions established
- Module: `platform` (single word, describes the MASVS category)
- Feature flag: `mobile-platform` (hyphenated, follows Cargo convention)
- Types: `SafeDeepLink`, `DeepLinkValidator`, `ClipboardPolicy`, `SafeWebViewUrl`, `WebViewUrlValidator`, `ScreenshotPolicy`, `PlatformRejection` (PascalCase, descriptive)
- EventKind variant: `PlatformSafetyViolation` (PascalCase, follows existing pattern)
- Test file: `platform_tests.rs` (matches `biometric_tests.rs`, `step_up_tests.rs` pattern)

## Test patterns that worked well
- BDD-style `given_*_when_*_then_*` test names matching runbook scenario tables
- Testing both `validate()` and `validate_with_events()` for security event emission
- Separate tests for happy path (valid input) and adversarial (rejected input)
- Testing policy objects with different `DataClassification` values

## Missing tests that should exist now
- Fuzz target `fuzz_deep_link` for `DeepLinkValidator` with arbitrary URL strings (deferred to M9 per runbook)
- Property tests for `ClipboardPolicy` across all `DataClassification` variants (deferred to M9)

## Rules for the next milestone
- Continue using `SecurityEvent::new(kind, severity, outcome)` constructor
- Feature-gate new mobile modules consistently (cfg attribute on module in lib.rs + cfg attribute in test file)
- `validate_with_events()` pattern works well for validators that emit security events — reuse in M5
- Always add wildcard `_` arm when matching `#[non_exhaustive]` enums from other crates
- Validator + output type pattern (instead of `TryFrom`) is appropriate when validation needs configuration

## Observations on Milestone 5
- `secure_resilience` is a new crate (not extending existing). Will need Cargo.toml setup, lib.rs, and workspace member registration.
- Environment detection (root/jailbreak, emulator, debugger) will produce signal types — similar to policy objects but with detection logic.
- App integrity verification will likely need hash comparison — ensure no actual cryptographic key material is embedded.

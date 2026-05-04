# Lessons Learned — sunlit-masvs Milestone 7

## What changed
- Extended `security_events` with mobile-specific log sanitization module (`mobile_redaction.rs`)
- Added `MobileRedactionEngine` for device identifier scrubbing (IMEI, IDFV, GAID/IDFA, MAC addresses) and GPS coordinate scrubbing
- Added `LogLevelEnforcer` with `LogLevel` enum for compile-time log level enforcement
- Registered module in `lib.rs` with public re-exports
- 20 BDD tests in `mobile_redaction_tests.rs` + 4 unit tests in module

## Design decisions and why
- **Separate `LogLevel` enum**: `SecuritySeverity` (Info/Low/Medium/High/Critical) represents security impact, not log verbosity. Created `LogLevel` (Trace/Debug/Info/Warn/Error) in `mobile_redaction` module for log-level filtering. These are orthogonal concerns.
- **Key-based UUID disambiguation**: UUIDs appear everywhere (event IDs, correlation IDs, device IDs). Rather than treating all UUIDs as device IDs, the engine uses the label key name to determine intent. Keys like `idfv`, `gaid`, `ad_id`, `device_*` trigger redaction; `correlation_id`, `event_id`, `request_id` are preserved.
- **No regex dependency**: Implemented pattern matching with simple string/byte operations to honor the "no new dependencies" contract. IMEI is 15-digit check, MAC is hex-pair-separator pattern, GPS is decimal coordinate pair parse.
- **Scrub before classify**: `MobileRedactionEngine.scrub_event()` runs before `RedactionEngine.process_event()` in the pipeline. This ensures device IDs are replaced with placeholder text before classification-level hashing/redaction.
- **Advertising IDs get distinct placeholder**: `[AD_ID_REDACTED]` vs `[DEVICE_ID_REDACTED]` — different privacy implications (ad tracking vs device identity).

## Mistakes made
- Initial test file used non-exhaustive `match` on `Option<&EventValue>` without `None` arm, causing compilation errors. Fixed by introducing a `get_classified_value()` helper function.
- First attempt used `SecuritySeverity::Debug` and `SecuritySeverity::Trace` which don't exist in the enum.

## Root causes
- Assumed `SecuritySeverity` would have debug/trace variants. Should have read the enum definition before writing tests.
- Rust's exhaustiveness checking caught the `match` issue at compile time.

## What was harder than expected
- UUID disambiguation: any UUID could be a device ID, correlation ID, or random identifier. Key-name heuristics are the practical solution but not perfect.

## Naming conventions established
- Module: `mobile_redaction` (follows `_` separation pattern of existing modules like `rate_limit`, `audit_chain`)
- Types: `MobileRedactionEngine`, `LogLevelEnforcer`, `LogLevel`
- Method: `scrub_event()` (distinct from `process_event()` used by `RedactionEngine`)
- Placeholders: `[DEVICE_ID_REDACTED]`, `[AD_ID_REDACTED]`, `[LOCATION_REDACTED]`
- Test file: `mobile_redaction_tests.rs`

## Test patterns that worked well
- Helper function `get_classified_value()` to extract and unwrap label values cleanly
- Separate test sections per feature area (device ID scrubbing, log level enforcement, integration, edge cases)
- BDD-style `given_*_when_*_then_*` test names
- Integration test composing `MobileRedactionEngine` + `RedactionEngine` to verify pipeline

## Missing tests that should exist now
- Fuzz target `fuzz_mobile_redaction` for arbitrary strings (deferred to M9)
- Property tests for: "no IMEI-format string survives scrubbing", "no MAC address survives scrubbing" (deferred to M9)
- Edge case: embedded device IDs within longer strings (currently only matches exact values)

## Rules for the next milestone
- `MobileRedactionEngine::scrub_event()` should be called before `RedactionEngine::process_event()` in any pipeline
- `LogLevel` is separate from `SecuritySeverity` — don't conflate them
- UUID-based device ID detection requires key-name heuristics; consider expanding the key list as new use cases emerge
- When extending existing crates, keep new functionality in separate modules rather than expanding existing files

## Observations on Milestone 8
- M8 adds smoke service routes; will need to wire up mobile security crates as dependencies
- The 15 new routes each test one MASVS control area
- Routes follow `/smoke/mobile/` prefix pattern

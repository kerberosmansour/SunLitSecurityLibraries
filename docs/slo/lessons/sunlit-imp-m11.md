# Lessons Learned — Milestone 11: Safe Types + Input Validation Hardening

**Date:** 2026-04-06  
**Milestone:** M11 — Safe types + input validation hardening

---

## 1. `SecureJson<T>` inner field is private — use `.into_inner()`

**What happened:** Test handlers tried `SecureJson(dto): SecureJson<CreateUserDto>` destructuring in integration tests living in external `tests/` crates.

**Root cause:** `pub struct SecureJson<T>(T)` — the tuple field is private. Destructuring in pattern position only works within the same crate.

**Fix:** All external tests must call `.into_inner()`:
```rust
async fn handler(extractor: SecureJson<Dto>) -> StatusCode {
    let dto = extractor.into_inner();
    ...
}
```

**Apply going forward:** Any new axum extractor wrapping a private tuple field must expose `into_inner()`. Document this in the handler examples so consumers don't hit it.

---

## 2. Clippy `manual_pattern_char_comparison` lint

**What happened:** `find(|c| matches!(c, '/' | '?' | '#'))` triggered `manual_pattern_char_comparison` under `-D warnings`.

**Fix:** Use the pattern slice syntax Clippy expects:
```rust
.find(['/', '?', '#'])
```

**Apply going forward:** When matching a closure that tests `char` equality against a small set, always use the array pattern form.

---

## 3. `LdapSafeString::try_from` always returns `Ok` by design

**What happened:** Reviewers might expect this to fail on injection-like input. It doesn't.

**Rationale:** LDAP escaping transforms dangerous chars (RFC 4515) rather than rejecting them — LDAP queries need to proceed with escaped values. The function emits a `BoundaryViolation` event when escaping was applied so the security team can monitor for injection attempts.

**Apply going forward:** When reviewing LDAP-related safe types, remember that **event-emitting-but-allowing** is intentional. Confirm the sidecar SIEM picks up `ViolationKind::InjectionAttempt` events from LDAP paths.

---

## 4. macOS sandbox blocks runtime health check

**What happened:** `cargo run -p secure_reference_service` failed with "Operation not permitted" under the macOS sandbox during E2E smoke tests.

**Root cause:** The macOS sandbox restricts process execution in certain environments.

**Impact:** The binary builds and tests pass; only the boot-up health check (`curl localhost:8080/health`) cannot be validated locally.

**Workaround:** Skip this step in macOS-sandbox environments; CI Linux runners will execute it successfully.

---

## 5. JSON byte-scanner depth/field counting correctness

**What happened:** Initial counting was off for colons inside string values (e.g. `{"url":"https://x"}` counted two fields instead of one).

**Fix:** The scanner correctly tracks `in_string` and `escape` state flags to skip structural characters inside string literals before incrementing the nesting depth or field counter.

**Apply going forward:** When extending `check_json_limits()`, always run through the test cases in `sunlit_imp_depth_limits.rs` which cover nested objects, arrays, and colons/braces inside strings.

---

## 6. `quick-xml` serde feature must be explicit

**Fix:**
```toml
quick-xml = { version = "0.36", features = ["serialize"] }
```
The default `quick-xml` feature set does NOT include the serde `Deserialize` support. Without `features = ["serialize"]`, `quick_xml::de::from_str::<T>()` does not compile.

---

## 7. `ViolationKind` variants were already defined in M4

`NestingTooDeep` and `TooManyFields` already existed in `attack_signal.rs` from M4. Reuse them. Do not re-add.

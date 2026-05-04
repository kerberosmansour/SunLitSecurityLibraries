# Lessons Learned — Milestone 12: Output Encoding Expansion + Security Headers

**Date:** 2026-04-06  
**Milestone:** M12 — Output encoding expansion + security headers

---

## 1. JS encoder E2E test assertion correctness

**What happened:** The initial E2E test for `JsStringEncoder` checked `!result.contains('\'')` — but escaping `'` to `\'` still leaves a `'` character in the output (preceded by `\`). The assertion was semantically wrong.

**Fix:** Assert the presence of the escape sequence (e.g. `result.contains("\\'")`), and separately assert absence of raw control characters (`\n`, `\r`, U+2028, U+2029, `\0`).

**Apply going forward:** When testing escape-based encoders (JS, CSS), always distinguish between:  
- "character is absent" (only valid for chars like `\0`, `\n`, `\r` that we replace entirely)  
- "escape sequence is present" (for `'`, `"`, `\` which are escaped-in-place, not removed)

---

## 2. CSS encoder uses unicode-escape notation

**Design choice:** CSS encoding uses `\XXXXXX` (6-digit hex unicode escape) for any non-alphanumeric, non-hyphen, non-underscore character. This is the most conservative and portable CSS escaping strategy, avoiding ambiguity with CSS property syntax.

**Apply going forward:** If a more permissive CSS allow-list is needed (e.g. allowing `.` in class names), extend the `needs_css_encoding` predicate but document the rationale clearly.

---

## 3. XmlEncoder encodes both `'` and `"` to named entities

**Design choice:** Both single and double quotes are encoded (`'` → `&apos;`, `"` → `&quot;`) to allow the encoded output to be safely used in both single-quoted and double-quoted XML attribute contexts.

---

## 4. `sanitize_uri_scheme` handles relative URIs and edge cases

**Design:** Relative URIs (starting with `/`), empty strings, query-only (`?...`), and fragment-only (`#...`) URIs are always allowed because they have no scheme. The colon detection only triggers when the scheme portion contains no forward slashes (preventing false positives for paths like `./path`).

**Apply going forward:** If new dangerous schemes are discovered (e.g. `jar:`, `chrome-extension:`), add them to `BLOCKED_SCHEMES`. The list is intentionally conservative.

---

## 5. Cross-origin headers added as struct fields with defaults

**Design:** The five new headers (COEP, COOP, CORP, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies) are stored as struct fields on `SecurityHeadersLayer` with hardcoded default values in `defaults` module. No new builder methods were added (not required by the milestone spec), keeping the change minimal.

**Apply going forward:** If callers need to override cross-origin headers, add `with_coep()`, `with_coop()` etc. builder methods following the existing `with_csp()` / `with_hsts()` pattern.

---

## 6. Zero-copy `Cow::Borrowed` fast path for all encoders

All three new encoders (`JsStringEncoder`, `CssEncoder`, `XmlEncoder`) correctly return `Cow::Borrowed` when the input contains no characters requiring encoding, matching the pattern established by `HtmlEncoder`. This ensures zero-allocation on the common case of already-safe strings.

# secure_output

[![crates.io](https://img.shields.io/crates/v/secure_output.svg)](https://crates.io/crates/secure_output)
[![docs.rs](https://docs.rs/secure_output/badge.svg)](https://docs.rs/secure_output)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Context-aware output encoding for every place an application emits data — HTML, JSON, URL, JS strings, CSS, XML, LDAP, shell (OWASP C4). Part of the [SunLit Security Libraries](https://github.com/kerberosmansour/SunLitSecurityLibraries) workspace.

## When to reach for this crate

- You're rendering server-side HTML and need an injection-safe encoder that's **zero-copy when input is already safe**.
- You're embedding user input into JSON inside a `<script>` tag (the classic `</script>` injection pitfall).
- You're building LDAP filters or shell argument strings and want explicit RFC-compliant encoders.
- You need to **sanitize URI schemes** so `<a href>` and `<img src>` can't host `javascript:` or `data:` attacks.

All encoders implement an open `OutputEncoder` trait so callers pick by *context*, not by guesswork.

## Install

```toml
[dependencies]
secure_output = "0.1"
```

## Quick example

```rust
use secure_output::{HtmlEncoder, JsonEncoder, UrlEncoder, sanitize_uri_scheme};
use secure_output::encode::OutputEncoder;
use std::borrow::Cow;

// HTML body or attribute encoding — zero-copy for safe strings.
let html: Cow<str> = HtmlEncoder.encode("<b>hi</b>");
assert_eq!(html, "&lt;b&gt;hi&lt;/b&gt;");

// JSON encoding that also escapes </script> for inline-script embedding.
let json: Cow<str> = JsonEncoder.encode(r#"</script><script>alert(1)</script>"#);
assert!(!json.contains("</script>"));

// URL percent-encoding per RFC 3986.
let url: Cow<str> = UrlEncoder.encode("hello world & friends");
assert_eq!(url, "hello%20world%20%26%20friends");

// Block dangerous URI schemes before emitting an href/src.
let safe = sanitize_uri_scheme("javascript:alert(1)");
assert!(safe.is_err()); // returns DangerousUriScheme
```

## What's inside

| Type | Encodes for |
|---|---|
| `HtmlEncoder` | HTML body and attribute context (zero-copy when safe). |
| `JsonEncoder` | JSON output, including `</script>` defense for inline-script embedding. |
| `UrlEncoder` | RFC 3986 percent-encoding. |
| `JsStringEncoder` | JavaScript string-literal context. |
| `CssEncoder` | CSS context via Unicode escape. |
| `XmlEncoder` | XML text and attribute context. |
| `ldap::LdapDnEncoder` | LDAP Distinguished Name (RFC 4514). |
| `ldap::LdapFilterEncoder` | LDAP search filter (RFC 4515). |
| `shell::ShellEncoder` | POSIX shell argument quoting. |
| `sanitize_uri_scheme` | Returns `DangerousUriScheme` for `javascript:`, `data:`, etc. |

## Compatibility

- MSRV: 1.78
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- Zero allocations on the safe-string fast path (returns `Cow::Borrowed`)
- Pure Rust, no system dependencies

## Status

Alpha.

## License

Dual-licensed under [MIT](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/main/LICENSE-APACHE) at your option.

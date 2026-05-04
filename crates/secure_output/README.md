# secure_output

[![crates.io](https://img.shields.io/crates/v/secure_output.svg)](https://crates.io/crates/secure_output)
[![docs.rs](https://docs.rs/secure_output/badge.svg)](https://docs.rs/secure_output)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Context-aware output encoding (OWASP C4). Part of the **SunLit Security Libraries** workspace.

Drop-in encoders for every output context an application emits, plus URI scheme sanitization to block `javascript:`, `data:`, and friends.

## Encoders

| Type | Purpose |
|---|---|
| `HtmlEncoder` | HTML body/attribute encoding (zero-copy for safe strings). |
| `JsonEncoder` | JSON output encoding that prevents `</script>` injection. |
| `UrlEncoder` | RFC 3986 percent-encoding. |
| `JsStringEncoder` | JavaScript string-literal encoding. |
| `CssEncoder` | CSS context encoding via Unicode escape. |
| `XmlEncoder` | XML text and attribute encoding. |
| `ldap::LdapDnEncoder` | LDAP Distinguished Name encoding (RFC 4514). |
| `ldap::LdapFilterEncoder` | LDAP search-filter encoding (RFC 4515). |
| `shell::ShellEncoder` | POSIX shell argument encoding. |
| `sanitize_uri_scheme` | Blocks dangerous URI schemes for href/src outputs. |

All implementations share an `OutputEncoder` trait so callers can pick the right encoder by context, not by guesswork.

## Install

```toml
[dependencies]
secure_output = "0.1"
```

## Status

Alpha.

## Links

- Workspace: https://github.com/kerberosmansour/SunLitSecurityLibraries

## License

Dual-licensed under MIT or Apache-2.0 at your option.

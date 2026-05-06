# `secure_output` — Developer Guide

> **OWASP C4**: Context-aware output encoding to prevent XSS, injection, and data exfiltration.

`secure_output` provides encoders for every output context you'll encounter: HTML, JavaScript, CSS, URLs, XML, and JSON-in-HTML. Each encoder is zero-copy when the input is already safe, and has no dependencies beyond `security_core`.

---

## Quick Start

```toml
[dependencies]
secure_output = "0.1.2"
```

---

## Core Concept: The `OutputEncoder` Trait

Every encoder implements the same trait:

```rust
pub trait OutputEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str>;
}
```

- Returns `Cow::Borrowed` when input needs no encoding (zero allocation)
- Returns `Cow::Owned` when characters need escaping
- All encoders strip null bytes (`\0`)

The trait is **open** — you can implement custom encoders for your own output contexts.

---

## Encoding by Context

### HTML Context — `HtmlEncoder`

Use when inserting user data into HTML text content or attributes:

```rust
use secure_output::{HtmlEncoder, OutputEncoder};

let enc = HtmlEncoder;

// XSS payload → safe HTML entities
let safe = enc.encode("<script>alert('xss')</script>");
assert_eq!(safe, "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;");

// Safe input → zero-copy (Cow::Borrowed)
let safe = enc.encode("Hello, World!");
assert!(matches!(safe, std::borrow::Cow::Borrowed(_))); // no allocation

// In a template:
let user_name = enc.encode(&user_input);
let html = format!("<p>Welcome, {user_name}</p>");
```

**Characters encoded:** `<` `>` `&` `"` `'` `/`

### JavaScript String Context — `JsStringEncoder`

Use when embedding user data inside a JavaScript string literal:

```rust
use secure_output::{JsStringEncoder, OutputEncoder};

let enc = JsStringEncoder;

// Escape special characters
let safe = enc.encode("user's \"name\"\nwith newline");
assert_eq!(safe, r#"user\'s \"name\"\nwith newline"#);

// Handle Unicode line/paragraph separators
let safe = enc.encode("text\u{2028}more\u{2029}data");
// U+2028 and U+2029 are escaped

// In a script tag:
let user_value = enc.encode(&user_input);
let js = format!("var name = '{user_value}';");
```

**Characters encoded:** `\` `'` `"` `\n` `\r` U+2028 U+2029

### CSS Context — `CssEncoder`

Use when embedding user data inside CSS values (e.g., `content:`, `background-image:`):

```rust
use secure_output::{CssEncoder, OutputEncoder};

let enc = CssEncoder;

// Prevents CSS injection (expression(), url(), etc.)
let safe = enc.encode("expression(alert(1))");
// Non-alphanumeric characters → CSS unicode escapes (\XXXXXX)

// Safe for CSS values
let user_color_name = enc.encode(&user_input);
let css = format!("content: '{user_color_name}';");
```

**Encoding rule:** All characters except `[a-zA-Z0-9_-]` are converted to CSS unicode-escape notation (`\XXXXXX`).

### URL Context — `UrlEncoder`

Use when embedding user data in URL query parameters:

```rust
use secure_output::{UrlEncoder, OutputEncoder};

let enc = UrlEncoder;

// Percent-encode special characters (RFC 3986)
let safe = enc.encode("hello world&q=1");
assert_eq!(safe, "hello%20world%26q%3D1");

// Unreserved characters pass through
let safe = enc.encode("simple-text_123.txt");
assert_eq!(safe, "simple-text_123.txt"); // no encoding needed

// In a URL:
let search_term = enc.encode(&user_query);
let url = format!("https://api.example.com/search?q={search_term}");
```

**Unreserved characters (not encoded):** `A-Z` `a-z` `0-9` `-` `_` `.` `~`

### XML Context — `XmlEncoder`

Use when embedding user data in XML text content or attributes:

```rust
use secure_output::{XmlEncoder, OutputEncoder};

let enc = XmlEncoder;

// Encode XML special characters
let safe = enc.encode("<tag attr=\"val\">");
assert_eq!(safe, "&lt;tag attr=&quot;val&quot;&gt;");

// In XML output:
let user_value = enc.encode(&user_input);
let xml = format!("<name>{user_value}</name>");
```

**Characters encoded:** `<` `>` `&` `"` `'`

### JSON-in-HTML Context — `JsonEncoder`

Use when embedding JSON inside an HTML `<script>` tag:

```rust
use secure_output::{JsonEncoder, OutputEncoder};

let enc = JsonEncoder;

// Prevents closing the script tag
let safe = enc.encode("</script>");
assert_eq!(safe, "<\\/script>");

// In an HTML template:
let json_data = enc.encode(&serialized_json);
let html = format!(r#"<script>var data = {json_data};</script>"#);
```

**This prevents the specific attack** where a JSON string containing `</script>` would prematurely close the `<script>` tag.

---

## URI Scheme Sanitization

Validate URI schemes before using them in `href`, `src`, or redirect locations:

```rust
use secure_output::sanitize_uri_scheme;

// Safe schemes
sanitize_uri_scheme("https://example.com").unwrap();  // ✓ Ok
sanitize_uri_scheme("http://example.com").unwrap();   // ✓ Ok
sanitize_uri_scheme("mailto:user@example.com").unwrap(); // ✓ Ok
sanitize_uri_scheme("/relative/path").unwrap();       // ✓ Ok
sanitize_uri_scheme("#anchor").unwrap();              // ✓ Ok
sanitize_uri_scheme("?query=value").unwrap();         // ✓ Ok

// Dangerous schemes — blocked
sanitize_uri_scheme("javascript:alert(1)").unwrap_err();  // ✗ XSS
sanitize_uri_scheme("data:text/html,<script>").unwrap_err(); // ✗ data URI
sanitize_uri_scheme("vbscript:MsgBox").unwrap_err();    // ✗ vbscript
sanitize_uri_scheme("file:///etc/passwd").unwrap_err();  // ✗ local file
sanitize_uri_scheme("blob:http://evil.com").unwrap_err(); // ✗ blob

// Case-insensitive
sanitize_uri_scheme("JAVASCRIPT:alert(1)").unwrap_err(); // ✗ still blocked
sanitize_uri_scheme("JaVaScRiPt:void(0)").unwrap_err();  // ✗ still blocked
```

### Using in Templates

```rust
use secure_output::sanitize_uri_scheme;

fn render_link(user_url: &str) -> String {
    match sanitize_uri_scheme(user_url) {
        Ok(()) => format!(r#"<a href="{}">Link</a>"#, user_url),
        Err(e) => format!("<span>Invalid link: blocked scheme '{}'</span>", e.scheme),
    }
}
```

---

## Choosing the Right Encoder

| Output Context | Encoder | Example Template |
|---|---|---|
| HTML text content | `HtmlEncoder` | `<p>{encoded}</p>` |
| HTML attribute value | `HtmlEncoder` | `<input value="{encoded}">` |
| JavaScript string | `JsStringEncoder` | `var x = '{encoded}';` |
| CSS value | `CssEncoder` | `content: '{encoded}';` |
| URL query parameter | `UrlEncoder` | `?search={encoded}` |
| XML text/attribute | `XmlEncoder` | `<name>{encoded}</name>` |
| JSON inside `<script>` | `JsonEncoder` | `<script>var d = {encoded};</script>` |
| `href`/`src` attribute | `sanitize_uri_scheme()` | `<a href="{validated}">` |
| LDAP DN component | `LdapDnEncoder` / `ldap::encode_dn()` | `cn={encoded},dc=example` |
| LDAP filter value | `LdapFilterEncoder` / `ldap::encode_filter()` | `(uid={encoded})` |
| OS shell argument | `ShellEncoder` / `shell::encode()` | `command {encoded}` |

---

## LDAP DN Encoding (RFC 4514)

Escape user input before embedding in LDAP Distinguished Name components:

```rust
use secure_output::ldap::encode_dn;

let safe = encode_dn("John+Smith,OU=Users");
assert_eq!(safe, "John\\+Smith\\,OU\\=Users");
```

Escaped characters: `,`, `+`, `"`, `\`, `<`, `>`, `;`, `=`. Leading `#` and leading/trailing spaces are also escaped. Null bytes are hex-escaped as `\00`.

---

## LDAP Filter Encoding (RFC 4515)

Escape user input before embedding in LDAP search filter assertions:

```rust
use secure_output::ldap::encode_filter;

let safe = encode_filter("user*admin");
assert_eq!(safe, "user\\2aadmin");
```

Escaped characters: `*`, `(`, `)`, `\`, NUL. Uses `\XX` hex notation.

---

## Shell Encoding (POSIX)

Escape user input for safe use as a POSIX shell argument:

```rust
use secure_output::shell;

let safe = shell::encode("file; rm -rf /");
assert_eq!(safe, "'file; rm -rf /'");
```

Uses single-quoting. Inside single quotes, no shell metacharacters are interpreted. Embedded single quotes are escaped as `'\''`. Null bytes are stripped.

> **Prefer `std::process::Command` argument arrays** over shell string interpolation where possible. Use this encoder as defense-in-depth when shell invocation is unavoidable.

---

## Custom Encoders

Implement `OutputEncoder` for your own output contexts:

```rust
use secure_output::OutputEncoder;
use std::borrow::Cow;

/// Encodes values for safe embedding in Markdown text
struct MarkdownEncoder;

impl OutputEncoder for MarkdownEncoder {
    fn encode<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let special_chars = ['*', '_', '`', '[', ']', '(', ')', '#', '>', '!', '|'];
        if !input.chars().any(|c| special_chars.contains(&c)) {
            return Cow::Borrowed(input); // fast path
        }
        let mut out = String::with_capacity(input.len() + 16);
        for c in input.chars() {
            if special_chars.contains(&c) {
                out.push('\\');
            }
            out.push(c);
        }
        Cow::Owned(out)
    }
}
```

---

## Performance Notes

All encoders use a two-phase approach:
1. **Scan phase**: Check if any characters need encoding
2. **Encode phase**: Only allocate and encode if needed

For safe inputs (no special characters), the encoder returns `Cow::Borrowed` — zero allocation, zero copy. This is the common case for most data and means output encoding has near-zero overhead.

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `OutputEncoder` | `encode` | Core trait (open — implement your own) |
| `HtmlEncoder` | `html` | HTML entity encoding |
| `JsonEncoder` | `json` | JSON-in-HTML `</script>` prevention |
| `UrlEncoder` | `url` | RFC 3986 percent-encoding |
| `JsStringEncoder` | `js` | JavaScript string literal encoding |
| `CssEncoder` | `css` | CSS unicode-escape encoding |
| `XmlEncoder` | `xml` | XML entity encoding |
| `LdapDnEncoder` | `ldap` | LDAP DN encoding (RFC 4514) |
| `LdapFilterEncoder` | `ldap` | LDAP filter encoding (RFC 4515) |
| `ShellEncoder` | `shell` | POSIX shell argument encoding |
| `encode_dn()` | `ldap` | Convenience free function for DN encoding |
| `encode_filter()` | `ldap` | Convenience free function for filter encoding |
| `shell::encode()` | `shell` | Convenience free function for shell encoding |
| `sanitize_uri_scheme()` | `uri` | URI scheme safety validation |
| `DangerousUriScheme` | `uri` | Error for blocked schemes |

# Inline-script encoding threat model

## Scope

This model covers the `secure_output` JavaScript string and JSON-in-HTML
helpers plus their copyable integration guidance. It is frozen at base
`1df3aef70ea240d5b5d14401baa5ac7a4dfb1af3` and addresses findings 4 and 5
from Codex Security run
`wfr_ba7e824e52f38743230cf3f9760ae39f61250e26e08e52cf854358c2cb7e3e51`.

## Assets and boundaries

- Same-origin script execution authority, session data available to page
  JavaScript, DOM integrity, and user-visible response content.
- Attacker-controlled Unicode text crosses a Rust output-encoding API before it
  is placed in either a JavaScript string literal or a serialized JSON document
  inside an HTML `<script>` raw-text element.
- The HTML tokenizer owns the outer raw-text boundary. The JavaScript parser
  owns string and expression syntax after the HTML tokenizer has retained the
  script element. A JSON serializer owns JSON grammar before HTML-boundary
  escaping.

## Threat scenarios

| ID | Source | Sink | Failure | Required control |
|---|---|---|---|---|
| `tm-inline-script-1` | Text containing `</script><script>marker()</script>` or a mixed-case variant | Inline JavaScript string inside `<script>` | `JsStringEncoder` preserves `<`, so the HTML tokenizer terminates the trusted script before JavaScript string escaping matters | Use a distinct inline-script string encoder that first preserves JavaScript string semantics and represents HTML-significant raw-text bytes as JavaScript Unicode escapes |
| `tm-inline-script-2` | Arbitrary `&str` such as `alert(1)` | Unquoted `var config = {value}` expression | `JsonEncoder` only neutralizes an HTML closing-tag sequence; it does not serialize or validate JSON grammar | Serialize a typed value to one complete JSON document, then apply the JSON-in-HTML boundary encoder to that serialized document |

## Security invariants

1. The public inline-script string encoder emits no literal `<`, `>` or `&` for
   attacker-controlled input and retains all existing JavaScript string-literal
   escapes, including quotes, backslashes, CR/LF, U+2028/U+2029 and null removal.
2. `JsStringEncoder` remains the standalone JavaScript string-literal API and is
   not described as sufficient for HTML raw-text.
3. `JsonEncoder` accepts an already serialized JSON document. Documentation
   never claims it turns arbitrary text into JSON or demonstrates unquoted raw
   interpolation.
4. Safe standalone and inline inputs remain zero-copy where their selected
   context requires no transformation.

## Residual limits

- Inline encoding does not supply CSP nonces, Trusted Types, template escaping,
  JSON serialization, DOM insertion policy, or URL validation. Consumers should
  prefer external scripts or non-executable JSON containers where practical.
- This milestone proves deterministic encoder output and copyable Rust examples;
  it does not execute a browser or claim protection for event-handler,
  `javascript:` URL, template-literal, CSS, HTML, or DOM API contexts.

Data classification: attacker-controlled page data is Confidential at most;
session material reachable after XSS is Restricted. Relevant controls: C3
Validate all Input & Handle Exceptions, C4 Address Security from the Start, C5
Secure by Default, and C7 Enforce Access Controls.

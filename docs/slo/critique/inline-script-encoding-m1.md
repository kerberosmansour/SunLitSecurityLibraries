# Inline-script encoding M1 critique

## CEO pass

The contract fixes two demonstrated copyable-library defects without widening
into a template engine, CSP framework or JSON serializer. The new type gives the
unsafe context a name that downstream users can review. Publication remains out
of scope until the coordinated release milestone.

Decision: accept.

## Engineering lead pass

A separate encoder avoids changing `JsStringEncoder` output for existing
standalone JavaScript consumers. Direct character matching is deterministic,
keeps the zero-copy fast path, and needs no dependency. Reusing the lexical
escape cases inside one module is preferable to routing through an intermediate
allocated string. The public re-export and rustdoc examples are required to keep
the API discoverable.

Decision: accept with tests for `Cow::Borrowed`, every inherited escape and the
three HTML-significant characters.

## Security pass

The original control reasoned at the JavaScript parser while the exploit occurs
first in the HTML tokenizer. A literal `<` is the decisive raw-text boundary;
escaping `<`, `>` and `&` as JavaScript Unicode escapes preserves the eventual
string value without exposing HTML-significant bytes. JSON boundary escaping is
valid only after a serializer has established JSON grammar. Mixed-case closing
tags, quotes, backslashes, CR/LF, U+2028/U+2029 and null bytes must be negative
tests. Documentation must state the residual contexts and must not imply CSP or
browser policy.

Decision: accept; fail closed on the exact scan witnesses and preserve the
serialize-then-encode order.

## QA pass

The red test must fail before production code exists and pass through the public
crate export afterward. Focused tests, the package suite and doctests, all-feature
workspace, Clippy, rustfmt and zero-warning rustdoc cover compatibility. Search
the changed guides for the prior unquoted `var config = {safe_data}` pattern and
for inline examples still using `JsStringEncoder`. Exact-head CI and an exact
merged-main Codex Security rescan remain shipping gates.

Decision: accept. No browser runtime claim is allowed from string assertions
alone; the observable contract is absence of raw HTML-significant bytes plus
preserved JavaScript string semantics.

## Final disposition

Proceed with M1 under the 14-file exact allow-list. No architecture, dependency
or policy exception is required. The user's standing autonomous authorization is
the milestone confirmation basis.

# Inline-script encoding M1 lessons

## What changed the design

The exploit is decided by the HTML tokenizer before the JavaScript parser sees
the string. Escaping quotes, slashes and newlines is necessary for JavaScript
syntax but cannot stop a literal `<` from beginning an HTML raw-text end tag.
The reliable design gives the nested HTML-plus-JavaScript context its own public
type and removes HTML-significant bytes while preserving the eventual
JavaScript string value.

The related documentation finding had the same boundary-shape error. A boundary
transform cannot establish grammar owned by a serializer. The typed value must
be serialized first, and only that complete JSON document may cross the
JSON-in-HTML boundary encoder.

## What worked

- A new context type preserved every existing `JsStringEncoder` output and
  avoided a source-compatible API silently changing semantics.
- The red test used the public re-export, so it proved both implementation and
  discoverability were absent before the fix.
- A direct output invariant, no literal `<`, `>` or `&`, covers mixed-case and
  variant end-tag witnesses without maintaining a tag-name blocklist.
- Keeping serialization outside `secure_output` avoided a new dependency and
  retained the crate's small, deterministic boundary-transform role.
- Running the complete workspace caught compatibility issues while package
  rustdoc gave a quick diagnostic when the earlier workspace documentation run
  appeared idle.

## Reusable rule

Name an output type after the complete parser context at the sink. When one
language is nested inside another, satisfy the outer parser first and then the
inner grammar. Do not describe a character transform as a serializer, parser or
policy engine.

## Follow-up

The smoke service's older `JsStringEncoder` plus `JsonEncoder` composition is
safe because it changes every `</` prefix before HTML parsing, but the new
single-purpose type would express that route more clearly. Its route and tests
were outside this confirmed allow-list, so the cleanup remains visible for a
later bounded milestone.

The exact merged-main scan closed both contracted findings and also produced a
larger unrelated queue. Treat a successful targeted rescan and whole-repository
security health as separate claims: this milestone can close, while the 27 new
findings and the scan's explicitly partial inventory coverage still require
their own bounded defensive work.

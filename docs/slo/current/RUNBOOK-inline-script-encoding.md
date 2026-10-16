---
id: inline-script-encoding
prefix: inline-script-encoding
version: 4
stack: Rust
ai_component: false
baseline: cargo test -p secure_output --locked
---
# Inline-script encoding repairs — confirmed M1

Close the two related medium-severity XSS findings in exact merged-main Codex
Security run
`wfr_ba7e824e52f38743230cf3f9760ae39f61250e26e08e52cf854358c2cb7e3e51`
at `6b99e38528ceba765a341ee54a6e2687e7607d4e`: an HTML raw-text breakout
through the JavaScript string encoder and a guide that inserts arbitrary text as
an unquoted JavaScript expression.

## Contract

- Add a public `InlineScriptStringEncoder` for a JavaScript string literal
  inside an HTML `<script>` element. It preserves `JsStringEncoder`'s lexical
  escapes and additionally emits JavaScript Unicode escapes for `<`, `>` and
  `&`, so attacker input cannot form an HTML raw-text end tag.
- Keep `JsStringEncoder` source compatible and explicitly scope it to standalone
  JavaScript resources or other non-HTML string-literal contexts.
- Keep `JsonEncoder` source compatible, but state that it transforms one already
  serialized JSON document for an HTML script boundary. It is not a serializer
  and does not make arbitrary `&str` safe as executable JavaScript syntax.
- Replace every copyable inline example in the changed guides with the correct
  context type or a serialize-then-boundary-encode sequence.
- Add no dependency, manifest, lockfile, version, workflow authority, release or
  publication change.

Threat model:
`docs/slo/design/inline-script-encoding-threat-model.md`.

Outcomes:

- `oc-inline-script-1`: the exact closing-script witness and mixed-case variants
  cannot create a literal HTML end tag after inline string encoding.
- `oc-inline-script-2`: the integration guide never treats arbitrary text as a
  complete JavaScript expression; JSON grammar is established before the
  HTML-boundary transformation.

BDD starts with a public API regression that does not compile before the new
context type exists. The green matrix covers raw-text witnesses, quotes,
backslashes, controls, Unicode separators, nulls, safe zero-copy input and
already serialized JSON. Existing `secure_output` tests and doctests remain
green. Browser runtime, cloud, AI, mobile device, TLA and Kani are not applicable:
this milestone adds one deterministic character encoder and documentation.

## M1 exact allow-list (14)

- `crates/secure_output/src/js.rs`
- `crates/secure_output/src/json.rs`
- `crates/secure_output/src/lib.rs`
- `crates/secure_output/tests/codex_security_inline_script.rs`
- `crates/secure_output/README.md`
- `docs/dev-guide/secure-output.md`
- `docs/dev-guide/integration-guide.md`
- `CHANGELOG.md`
- `docs/slo/current/RUNBOOK-inline-script-encoding.md`
- `docs/slo/design/inline-script-encoding-threat-model.md`
- `docs/slo/critique/inline-script-encoding-m1.md`
- `docs/slo/verify/inline-script-encoding-m1.md`
- `docs/slo/lessons/inline-script-encoding-m1.md`
- `docs/slo/completion/inline-script-encoding-m1.md`

Exemplars: existing `JsStringEncoder` lexical escapes, the already serialized
JSON flow in `secure_smoke_service`, `OutputEncoder`'s `Cow` contract and the
context-specific HTML/CSS encoders. Anti-exemplars: changing `<` to `<\/` in
arbitrary text, passing raw text to `JsonEncoder` and interpolating it unquoted,
or claiming JavaScript lexical escaping controls the HTML tokenizer.

Forbidden shortcuts: dependency additions, custom JSON parsing, raw expression
interpolation, weakening existing JS escapes, renaming or removing existing
public types, using HTML entity encoding inside JavaScript, claiming CSP is
implemented, or editing outside the exact allow-list.

## Milestone tracker

| Milestone | Status | Started | Finished |
|---|---|---|---|
| M1 inline-script string and JSON guidance repair | locally verified; exact-head CI and merged-main scan pending | 2026-10-16 | — |

The user's standing instruction to continue autonomously with the SLO skills and
publish when needed is the confirmation basis for this milestone and allow-list.

## M1 evidence log

| Gate | Evidence | Result |
|---|---|---|
| BDD red | Public regression failed to compile before the new exported context type existed; log SHA-256 `abab318b86c6c0255115bec21586a7cd2646eafbab916edb5cd3bfc20e0128cf` | pass |
| BDD green | `cargo test -p secure_output --test codex_security_inline_script --locked` | 4/4 pass |
| Compatibility | `cargo test --workspace --all-features --locked` | pass, including 22 `secure_output` doctests |
| Static/docs | workspace all-target/all-feature Clippy and zero-warning rustdoc; rustfmt and `git diff --check` | pass |
| Supply chain | cargo audit, locked cargo-deny and locked cargo-vet | pass under existing policy |
| OSV | official pinned OSV-Scanner 2.7.0; 6 locks, 1,448 package occurrences; JSON SHA-256 `6cea97a78ce4454665abdde3ede39bbd5f76050c30914613c59f1de2a4053ed0` | 0 malicious findings; four unchanged tracked vulnerability findings |
| SAST/secrets | Semgrep Rust/OWASP SHA-256 `d7abc8addd7de8e578da7c2bc43f65bc19717852870f37fdb05a852d4b483837`; secrets SHA-256 `99f0b65f231acfeb2fe21270e58d0706ca1408bcc81f58eaabedea29bf80c73f` | 0 findings/errors |
| Dependency graph | manifests and lockfiles byte-unchanged | pass |
| Shipping | exact-head CI, merge verification and exact merged-main Codex Security rescan | pending |

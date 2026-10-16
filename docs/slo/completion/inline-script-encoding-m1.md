# Inline-script encoding M1 completion

## Delivered behavior

- `InlineScriptStringEncoder` now represents a JavaScript string placed inside
  an HTML `<script>` element. It retains JavaScript lexical escaping and emits
  `<`, `>` and `&` as JavaScript Unicode escapes, preventing attacker text from
  forming an HTML raw-text end tag.
- `JsStringEncoder` remains source compatible and is explicitly scoped to
  standalone JavaScript or other non-HTML string-literal contexts.
- `JsonEncoder` is documented as a transform for one already serialized JSON
  document. Copyable guides serialize typed data before applying it and no
  longer interpolate arbitrary text as executable JavaScript.
- The changelog, crate README, developer guide, public re-export and rustdoc all
  describe the new context boundary and its limits.

## Verification summary

- Public BDD regression: red before implementation, 4/4 green afterward.
- Locked all-feature workspace tests and doctests passed.
- Workspace Clippy, formatting and zero-warning rustdoc passed.
- Cargo audit, deny and vet passed under the repository's visible policy.
- Official OSV 2.7.0: six locks, 1,448 package occurrences, zero malicious
  advisories, four unchanged tracked vulnerability records, admission exit 0.
- Supplementary Semgrep Rust/OWASP and secrets scans: zero findings/errors.
- No dependency, manifest, lockfile, version, release or workflow change.

## Shipping handoff

Local M1 verification is complete. Exact-head CI, verified merge inspection and
an exact merged-main Codex Security rescan remain mandatory before final closure.
This milestone does not publish crates or change the coordinated release
version; publication remains governed by its separately confirmed runbook.

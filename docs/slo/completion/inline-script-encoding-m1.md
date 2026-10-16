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
- Implementation PR #152 passed 33 exact-head checks and merged as GitHub-
  verified commit `6f1da2a1604b64586d8b453d03297329ecb92a32`; its tree exactly matches the
  reviewed head tree.
- The exact-merge Codex Security rescan completed without a validation warning.
  Its full report and findings artifact contain neither frozen XSS title and no
  finding path in the three repaired source/guide files.

## Shipping result

M1 is complete. The rescan identified 27 unrelated defensive findings (20
medium and seven low), which are inputs to the next bounded remediation
milestones. Its coverage was partial, with full review receipts for 246 of 810
inventory files, so the closure is limited to the two contracted findings.

This milestone does not publish crates or change the coordinated release
version; publication remains governed by its separately confirmed runbook.

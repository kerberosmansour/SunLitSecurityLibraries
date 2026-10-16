# Inline-script encoding M1 verification

## Final result

M1 passes local verification, exact-head CI, verified merge inspection and the
exact merged-main Codex Security rescan. Both frozen findings are absent from
the complete report and findings artifact.

## Acceptance evidence

| Outcome | Evidence | Result |
|---|---|---|
| `oc-inline-script-1` / CWE-79 | Before implementation, the public regression did not compile because no inline-script context type existed. The final four-test suite proves the exact closing-script witness, mixed-case forms, comment syntax and ordinary `<`, `>` and `&` emit none of those literal HTML-significant bytes. It also proves inherited quote, slash, CR/LF, U+2028/U+2029 and null handling plus the zero-copy safe path. | pass |
| `oc-inline-script-2` / CWE-79 | The integration guide now accepts a serializable typed value, establishes one complete JSON document with `serde_json::to_string`, and applies `JsonEncoder` only afterward. Rustdoc and guide text explicitly reject the claim that the encoder serializes or validates arbitrary expressions. | pass |
| Compatibility | `cargo test --workspace --all-features --locked` passed, including the new 4/4 regression set, all existing tests and 22 `secure_output` doctests. The original `JsStringEncoder` behavior and public name remain unchanged. | pass |
| Static and docs | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked`, rustfmt and `git diff --check` passed. | pass |
| Supply chain | `cargo audit` reported no unaccepted advisory; `cargo deny --locked check` ended with advisories/bans/licenses/sources OK; `cargo vet --locked` succeeded with 146 fully audited, 49 partially audited and 305 exempted packages. | pass |
| Scope | Every changed path is in the 14-path contract. No manifest, lockfile, workflow, release, version, browser, AI, cloud, crypto or state-machine behavior changed. | pass |

The older smoke service composes `JsStringEncoder` with `JsonEncoder`, which
still breaks every literal `</` sequence and is not the frozen vulnerable
dataflow. Replacing that safe legacy composition with the clearer new type would
touch files outside this milestone's confirmed allow-list, so it remains a
bounded API-cleanup candidate rather than a silent scope extension.

## Dependency and scanner evidence

This milestone adds no dependency and leaves all manifests and lockfiles
unchanged. The repository's checksum-pinned official OSV-Scanner 2.7.0 scanned
six resolved lockfiles and 1,448 package occurrences. It found no `MAL-*`
advisory and retained the four already tracked vulnerability records for `rsa`
0.9.10, `smartstring` 1.0.1, `xxhash-rust` 0.8.15 and the Semgrep tool's `mcp`
1.29.0. Those records belong to the separately staged dependency batches; this
milestone neither admits nor executes a new package. OSV cannot establish the
absence of unknown malware.

- OSV JSON SHA-256:
  `6cea97a78ce4454665abdde3ede39bbd5f76050c30914613c59f1de2a4053ed0`.
- OSV receipt SHA-256:
  `c75369e9afd067248a082cf6380aa49745f1fba8b5614df2771d511ba6bfd9da`.
- Semgrep Rust/OWASP JSON SHA-256:
  `d7abc8addd7de8e578da7c2bc43f65bc19717852870f37fdb05a852d4b483837`.
- Semgrep secrets JSON SHA-256:
  `99f0b65f231acfeb2fe21270e58d0706ca1408bcc81f58eaabedea29bf80c73f`.
- Red-test log SHA-256:
  `abab318b86c6c0255115bec21586a7cd2646eafbab916edb5cd3bfc20e0128cf`.

Both Semgrep scans completed with zero findings and zero parse errors over the
changed Rust surfaces and documentation. Repository CI remains authoritative
for its separately admitted Semgrep toolchain.

## Shipping and independent rescan evidence

Implementation PR #152 reviewed head
`38beb10d1f1a7992b3925fba35e2fe568e264168` and passed all 33 reported checks.
GitHub squash-merged it as verified commit
`6f1da2a1604b64586d8b453d03297329ecb92a32`, with sole parent
`1df3aef70ea240d5b5d14401baa5ac7a4dfb1af3` and tree
`31012826b1ca5c2c0a3d1933b9f45f9b1ad634d3`. That tree is identical to the
reviewed head tree, and the commit retains the DCO sign-off.

Codex Security run
`wfr_7372fe361857e9d66b8faddc5128ebbb58cf0c13f95bae504b0b9e72c5637836`
completed without a validation warning against that exact merge. Its complete,
paginated artifacts establish:

- report SHA-256
  `8c148350b6a38a212f28194ca22dd74bdf41418ee5bbe3533148dd1851043f12`;
- findings SHA-256
  `89dc929a5f94135d17890a6b628748afa0c263c2a35e0ad8d112f3b7af4c4cf2`;
- scan-manifest SHA-256
  `0ffc25406474f601cc4a83818828d39e2fd3d14712df0ea2f87c60a133ec9732`;
- coverage SHA-256
  `e578799fe2096016b7b56a5ac6871b2885f58861665bda604754c02d7fc41437`.

Neither `JsStringEncoder leaves script-closing tags intact despite inline-script
guidance` nor `Integration example inserts raw user-derived text as executable
JavaScript` appears in the report or findings artifact. The report also names
none of `crates/secure_output/src/js.rs`, `crates/secure_output/src/json.rs` or
`docs/dev-guide/integration-guide.md` as a finding path. The scan reported 27
unrelated defensive findings (20 medium and seven low); they remain in the
separately sequenced remediation queue rather than altering this frozen scope.

The scan's repository coverage is explicitly partial: 246 of 810 inventory
files received full review receipts. This closure therefore establishes the two
contracted findings at the exact merge, not a claim that the entire repository
is free of vulnerabilities.

## Residual limits

The evidence establishes deterministic encoded output, not browser execution.
The new type does not add CSP, Trusted Types, JSON serialization, surrounding
quotes, DOM policy, event-handler encoding or URL validation. Callers must
select the type that matches the actual sink and retain their outer HTML and
script policy.

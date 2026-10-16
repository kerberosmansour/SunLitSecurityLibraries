# High input boundaries M1 verification

## Result

M1 passed local verification at signed implementation commit
`f9ed2bf10b4cc8143e511fc33ac99952f61547b9`. The three frozen high-severity
dataflows now fail closed: browser-ambiguous URI text is rejected and the guide
encodes accepted attributes, Axum JSON/XML bodies stop at the configured byte
cap, and SafeUrl classifies and retains one canonical parser result.

Exact-head CI and the merged-main Codex Security scan remain shipping gates.

## Acceptance evidence

| Outcome | Evidence | Result |
|---|---|---|
| `oc-high-input-boundaries-1` / CWE-79 | Before implementation, two hostile URI groups passed. The final 3-test suite rejects leading/embedded browser controls, whitespace, quotes, backticks, angle brackets, backslashes, network-path references and unapproved schemes while preserving documented HTTP(S), mailto and relative inputs. The copyable sink composes `sanitize_uri_scheme` with `HtmlEncoder.encode`. | pass |
| `oc-high-input-boundaries-2` / CWE-770 | Before implementation, both witnesses consumed all 128 four-byte frames and XML ignored the request extension. The final JSON and XML tests set an 8-byte request cap and prove rejection after at most three frames: the permitted 8 bytes plus one rejecting frame. Both return 413 and use one shared collector. | pass |
| `oc-high-input-boundaries-3` / CWE-918 | Before implementation, decimal, shortened, octal-like, hexadecimal and backslash destinations were accepted and the raw value was retained. The final suite rejects all witnesses, credentials, fragments and trailing-dot loopback, confirms canonical output, and exercises the same protected-address policy on resolved IPs. | pass |
| Compatibility | `cargo test -p secure_output --locked`, `cargo test -p secure_boundary --all-features --locked`, both default/all-feature workspace suites, and secure_boundary's none/axum/actix/both matrix passed. | pass |
| Static and docs | All-feature workspace Clippy with warnings denied, rustfmt, and all-feature rustdoc with warnings denied passed. Semgrep Rust/OWASP and secrets scans reported 0 findings and 0 errors across the four changed production files. | pass |
| Supply chain | Cargo audit reported 0 unaccepted vulnerabilities; cargo-deny reported advisories/bans/licenses/sources ok; cargo-vet succeeded with 146 fully audited, 49 partially audited and 305 exempted packages. | pass |
| Scope | `git diff --check` is clean and every changed path is in the 21-path contract allow-list. No UI, AI, cloud resource, crypto primitive or state-machine behavior was introduced; browser UI, DAST, TLA and Kani are not applicable. | pass |

## Dependency admission and provenance

Admission completed before any candidate build, procedural macro, test or
lifecycle script. Offline metadata resolution retained 514 package identities.
The manifest changes only add direct edges to packages already present in the
locked graph: `url` 2.5.8 for production parsing and `futures-util` 0.3 for the
stream witness.

- `url` 2.5.8 came from the crates.io index and its cached archive matched lock
  checksum `ff67a8f4004bc1d4cbd7a5e7747b48e6b9741793ee1129827ca70f4bc86b8d47`.
  Its manifest declares `build = false`, MIT/Apache-2.0 licensing and the Servo
  `rust-url` repository. The crates.io owner set includes the Servo/rust-url
  group and established maintainers.
- Official checksum-pinned OSV-Scanner 2.7.0 inspected 6 lockfiles and 1,448
  package occurrences. It retained four existing reviewed vulnerability records
  (`rsa` 0.9.10, `smartstring` 1.0.1, `xxhash-rust` 0.8.15 and Semgrep tool
  `mcp` 1.29.0), found 0 `MAL-*` records and exited successfully under the
  repository's exact bounded policies. This is not a claim that unknown malware
  is absent.
- OSV JSON SHA-256:
  `6cea97a78ce4454665abdde3ede39bbd5f76050c30914613c59f1de2a4053ed0`.
  Graph-diff SHA-256:
  `6acd6e3eda6253ade07e489c46d34119584a736f64038558cf191452d92ee00e`.
  Owner evidence SHA-256:
  `46c63b55a84db88fad9d2dffbe1e392337fb8bc8d890d02bb1e30c87fb707513`.

## Static evidence

- Semgrep 1.156.0 Rust/OWASP JSON SHA-256:
  `0fa7253e9a303b681b08a0b6a60fd3eb9ee0bf9d4e78d1cc3727049a6f7bef0e`.
- Semgrep 1.156.0 secrets JSON SHA-256:
  `bdf6d4a91a25bdadbea84c5e86ae2c06918f7536c1ed98a1f959f3969029d7a4`.
- Consolidated local verification SHA-256:
  `3a1ff44ce887bb40091628c1f8b0b9328e57f3d2a4990287f7581c64f569e247`.

Repository CI repeats SAST with its separately admitted, hash-pinned Semgrep
1.180.0 graph. The local result is supplementary rather than a replacement for
that exact-head gate.

## Residual limits

SafeUrl cannot establish DNS or connection authority. Consumers must bound name
resolution, validate every answer with `SafeUrl::validate_resolved_ip`, and pin
one approved address through connection establishment. URI validation does not
replace sink encoding. Upstream proxies, connection limits and request timeouts
remain deployment controls around the in-process body cap.

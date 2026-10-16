# Reference-service tenant mutation M1 verification

## Result

M1 passes local, exact-head CI, merge-integrity and exact merged-main security
verification. The frozen cross-tenant mutation finding is absent from the full
Codex Security report and findings artifact at the verified merge commit.

## Acceptance evidence

| Outcome | Evidence | Result |
|---|---|---|
| `oc-reference-tenant-1` / CWE-862, CWE-863 | Before implementation, cross-tenant PUT returned `200`; after the repair it returns `403`, and a same-tenant GET proves name, tenant and owner remain unchanged. | pass |
| `oc-reference-tenant-2` / CWE-862, CWE-863 | Before implementation, cross-tenant DELETE returned `200`; after the repair it returns `403`, and the original tenant can still retrieve the unchanged item. | pass |
| `oc-reference-tenant-3` | `resource_for_item` derives UUID, tenant and owner only from the stored `ItemResponse`. GET holds the read lock through authorization; PUT and DELETE hold the write lock through authorization and mutation. | pass |
| Compatibility | `cargo test -p secure_reference_service --test e2e_sunlit_m8 --locked` passes 19/19, including same-tenant CRUD, GET isolation, role checks, validation and missing-item behavior. The locked all-feature workspace suite and doctests pass. | pass |
| Static and docs | Workspace all-target/all-feature Clippy with warnings denied, zero-warning all-feature rustdoc, rustfmt and `git diff --check` pass. | pass |
| Scope | Every changed path is in the 10-path contract. No manifest, lockfile, dependency identity, version, release, workflow, authentication or storage-format change occurred. | pass |

## Dependency and scanner evidence

This milestone adds no dependency and leaves every manifest and lockfile
unchanged. The repository's checksum-pinned official OSV-Scanner 2.7.0 scanned
six resolved lockfiles and 1,448 package occurrences. It found no `MAL-*`
advisory and retained the four already tracked vulnerability records for `rsa`
0.9.10, `smartstring` 1.0.1, `xxhash-rust` 0.8.15 and the Semgrep tool's `mcp`
1.29.0. OSV cannot establish the absence of unknown malware.

- OSV JSON SHA-256:
  `6cea97a78ce4454665abdde3ede39bbd5f76050c30914613c59f1de2a4053ed0`.
- OSV receipt SHA-256:
  `c75369e9afd067248a082cf6380aa49745f1fba8b5614df2771d511ba6bfd9da`.
- Semgrep Rust/OWASP JSON SHA-256:
  `aef0fe58e77addc9c44cb5c7df45dd1a5b6d39e69e4c9c1bd1f10e777625d2c4`.
- Semgrep secrets JSON SHA-256:
  `6b9874f35b8131282d93057ec0c9373af2108cd238d0feda7978f47540069b60`.
- Red-test log SHA-256:
  `8bf6be49f29d29bd32a9ee242a880d06d627aba3d030a6582b8ea19c03ce36b1`.

Cargo audit reported no unaccepted advisory. Locked cargo-deny ended with
advisories, bans, licenses and sources OK. Locked cargo-vet succeeded with 146
fully audited, 49 partially audited and 305 exempted packages. Semgrep 1.156.0
scanned 792 tracked files with zero Rust/OWASP findings and zero secrets
findings; exact-head CI retained the admitted toolchain and passed all 33
reported checks.

## Shipping evidence

Implementation PR #154 reviewed signed head
`f6d019ed5dc7966f3a4af3b258ffed10440f8ba4` and passed 33 exact-head checks.
Its verified squash merge is
`1beb2fe7915378ee9f7640909528ee6ef8657357`, with sole parent
`e14dd92a06a5e53447d5da92822b1eb4eabbe65e`. The reviewed head and merge have
the same tree, `cf02d718ebb7ab37c888d968a509718e99984239`, and `origin/main`
resolved to the merge during inspection.

Codex Security run
`wfr_c456201e84a7e0aa5a30c6dc00a51653ea5717b5bc87ec15c0c80517da8c85b2`
completed against that exact merge without a validation warning. Its manifest
records complete whole-repository coverage with no excluded paths. Neither the
frozen title `Reference-service update and delete routes omit tenant
authorization` nor `crates/secure_reference_service/src/routes/items.rs`
appears in the report or findings artifact. The scan retained 37 unrelated
findings: 2 high, 34 medium and 1 low. They require separate bounded work and do
not weaken this finding-specific closure.

- Report SHA-256:
  `1607805640a6433d5e2d0a0fbfbce279a64079d986059ce5a940ec60868fc62d`.
- Findings SHA-256:
  `988e31d7b724d8c9938c0e11d3a610d12dfd46d0162abfc82bd2193c2017704d`.
- Manifest SHA-256:
  `b0f91fff5b02c6fcdf68f619d382c4a440a3d44df6894f2f019dc17c19aa5b88`.
- Coverage SHA-256:
  `997dc201af8d048cb25169b3477a91f6aa47a581dd64b374e9946239542c40aa`.

## Residual limits

The in-memory reference service holds a Tokio lock across authorization to make
the example's state transition atomic. A production datastore should enforce
the same rule with a transaction, conditional/versioned write or equivalent.
This milestone does not qualify the development authentication headers for
production, add owner-only policy or claim complete repository security. The
37 unrelated merged-main scan findings remain explicit follow-up work.

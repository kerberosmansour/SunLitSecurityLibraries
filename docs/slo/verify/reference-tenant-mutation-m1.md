# Reference-service tenant mutation M1 verification

## Local result

M1 passes local verification. The result remains provisional until the
implementation PR passes exact-head CI and an exact merged-main Codex Security
scan confirms that the frozen cross-tenant mutation finding is absent.

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
findings; exact-head CI remains authoritative for its admitted toolchain.

## Residual limits

The in-memory reference service holds a Tokio lock across authorization to make
the example's state transition atomic. A production datastore should enforce
the same rule with a transaction, conditional/versioned write or equivalent.
This milestone does not qualify the development authentication headers for
production, add owner-only policy or claim complete repository security.

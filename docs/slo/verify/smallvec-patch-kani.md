# SmallVec patch M2 verification

Status: complete for local milestone evidence; GitHub required checks remain a
merge gate on the exact reviewed commit.

## Formal evidence

Kani 0.68 is the repository-approved pin. The frontend source, lock and binary
receipt match the repository recipe; the independently downloaded backend bundle
matches its official SHA-256 and all installed files. Resolution is locked and
network access is disabled during proof runs.

| Representation / harness | Bound | Result |
|---|---:|---|
| Enum, SmallVec 1.15.1 zero-inline Box keep-rest | 20 | Fails: value assertion and deallocated-object read; 2/930 checks failed. |
| Enum, SmallVec 1.15.2 identical keep-rest | 20 | Passes: 0/930 failed, seven unreachable. |
| Enum, candidate initialization and inline/heap `from_vec` | 20 | Passes: 0/501 failed, six unreachable. |
| Enum, candidate arbitrary three-byte repeated spill/unspill | 12 | Passes: 0/436 failed, five unreachable. |
| Union, candidate arbitrary three-byte repeated spill/unspill | 12 | Passes: 0/397 failed, five unreachable. |
| Union, candidate zero-inline Box keep-rest | 20 | Unverified: stopped after roughly 7 GiB and four minutes; no result accepted. |

The proof inputs are concrete for keep-rest and initialization/from-vec, and
arbitrary over three `u8` values for repeated spill/unspill. There are no stubs
or concurrency models. These bounds establish only the named paths and inputs.

## Native candidate evidence

Four focused tests pass with union disabled and enabled: the concrete keep-rest
regression, initialization/from-vec, repeated spill/unspill, and aligned/ZST/drop
accounting. The 1.15.1 UB-producing case was not executed natively.

## Repository and admission verification

- Formatting and clippy pass with warnings denied.
- Default and all-feature workspace suites pass, including doctests.
- All-feature documentation passes with rustdoc warnings denied.
- Native dependency guard self-test and the aarch64 macOS platform check pass.
- The isolated HMAC graph excludes `rsa`; its two integration tests, one unit
  test and six real consumer/startup scenarios pass.
- Official checksum-verified OSV 2.7.0 scans seven resolved locks and 1,643
  package occurrences with exit 0. The root report retains the three unchanged,
  exact, owned and expiring exceptions for `rsa` 0.9.10 (`RUSTSEC-2023-0071`),
  `smartstring` 1.0.1 (`RUSTSEC-2026-0249`) and `xxhash-rust` 0.8.15
  (`GHSA-6g2r-675j-hx59`); all expire 2026-11-14 and none is `MAL-*`.
- Offline cargo-vet succeeds: 146 fully audited, 49 partially audited and 305
  exempted.
- Four maintenance-workflow and 48 script tests pass. The OSV non-zero lines in
  the script test output are deliberate fail-closed fixtures whose tests pass.

GitHub required checks remain the delivery gate and must pass on the exact
reviewed commit before merge.

No whole-crate safety, Miri, optional debugger feature, code-generation
performance or deployment qualification is claimed.

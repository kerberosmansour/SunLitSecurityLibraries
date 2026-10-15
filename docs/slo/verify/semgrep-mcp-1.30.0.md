# Semgrep MCP advisory M1 verification

## Result

M1 passed at signed implementation head
`bf3a7f71850d4c0ac00a2dc3b25b24595e891a4a`. The complete admitted Semgrep
graph works on the intended Ubuntu/Python 3.11 platform. The MCP advisory remains
in the raw OSV evidence and is governed by one exact exception expiring on
2026-10-29.

## Acceptance evidence

| Scenario | Evidence | Result |
|---|---|---|
| BDD-M1-1 | Official metadata resolution of Semgrep 1.180.0 with MCP 1.30.0 fails because Semgrep declares `mcp==1.29.0`. The Linux dry-run log SHA-256 is `6a797ab056401f6bad150129307db6c48fc1bca0e8ad95c301cb0bc1ee1d19b0`. Semgrep 1.181.0 was separately checked and retains the exact constraint. | pass |
| BDD-M1-2 | The removal-only head `59811895fba4fc9d70b2e52f85a07dcbf1e12da3` failed Semgrep run `38815832116`, job `116700249807`, when the common CLI path imported `semgrep.mcp.models` and then missing Pydantic. Preserved log SHA-256: `c80bb73b6c250acc053181f32e55f09100b7a337358d5a0c602e1c1d06f46577`. | pass: unsafe design rejected |
| BDD-M1-3 | Official checksum-pinned OSV-Scanner 2.7.0 inventoried 6 locks and 1,448 package occurrences before installation. The raw report contains 4 vulnerability findings, including MCP 1.29.0 with GHSA-84m7-p3x7-pcfv and CVE-2026-59951, and 0 malware findings. Raw/summary/receipt SHA-256: `666347ab2559e00445b838f09318eb45000461944225468239fa70c25fbd6307`, `c5e7a5856b6b7f72595de2262ee1ab68f38de890afb2fc076b7e0dacaf07d29c`, `c6fdc5aa2a52153d3d57a41375793b51bd84e9fc20ae4d28dca942cef5366f4a`. | pass |
| BDD-M1-4 | `python3 -m unittest scripts.test_osv_dependency_gate` passed 31 tests. The added mutations cover missing review, path/ecosystem/version/advisory drift, expiry, an overlong window, stale findings, strict schema and a `MAL-*` alias. Duplicate matching also fails because every finding requires exactly one record. | pass |
| BDD-M1-5 | Semgrep run `38816946688`, job `116704008321`, installed only hash-pinned binary wheels with `--no-deps`, then ran 329 rules over 762 tracked files with 0 findings. Log SHA-256: `cd154bb59a5b4e65d96d34b306883eee8123efea96d26c74370d4882044c6f13`. No server command was invoked. | pass |
| BDD-M1-6 | Exact-head runs passed: CI `38816946694`, Semgrep `38816946688`, CodeQL `38816946916`, scope drift `38816946744`, and Dependabot governance `38816946972`. CI includes Linux, macOS, Windows, supply-chain, feature matrices, package, docs, secret and dependency-review gates. `git verify-commit` validated the ED25519 signature and the commit retains DCO sign-off. | pass |

## Provenance review

- Semgrep 1.180.0 Linux wheel SHA-256:
  `16db2e2706ab814a975eeec25debfad49abba846b7c513d88e041447152f8447`.
- MCP 1.29.0 wheel SHA-256:
  `f5a075bb611f23d6f4d080c6a1699fa62772eebc562ba9e66b306ddde1c755f7`.
- Rejected fixed MCP 1.30.0 wheel SHA-256:
  `666edb5009503e1047c9d60346a756f94b261f05cc2625f23d41c728ffc484d0`.
- The requirements graph is byte-identical to `origin/main`; this milestone adds
  no direct or transitive dependency.

## Limits

MCP 1.29.0 remains vulnerable when its stateful Streamable HTTP server is
operated. This repository does not start or expose that path. The exception does
not certify the package or hide the advisory, and CI will stop accepting it on
2026-10-29. OSV covers known records only and cannot prove the absence of unknown
malware.

# High input boundaries M1 completion

## Delivered behavior

- Browser-ambiguous URI syntax and attribute delimiters fail closed; documented
  HTML sinks encode accepted values.
- Axum JSON and XML extractors enforce the configured limit while consuming body
  frames and share the same overflow/error mapping.
- SafeUrl uses the locked WHATWG parser, rejects ambiguous authorities and
  protected typed hosts, and returns the exact canonical value it classified.
  Resolved-address validation is available for caller-owned DNS pinning.

The public function signatures remain source compatible. Canonical SafeUrl
serialization and stricter rejection are intentional security behavior changes
and are recorded in the changelog and migration guidance.

## Verification summary

- Signed+DCO implementation commit:
  `f9ed2bf10b4cc8143e511fc33ac99952f61547b9`.
- Focused regressions: URI 3/3 and input boundaries 6/6 passed.
- Locked default and all-feature workspace suites passed, including doctests.
- secure_boundary none/axum/actix/both feature configurations passed.
- Workspace Clippy, formatting and zero-warning rustdoc passed.
- Cargo audit, deny and vet passed under the repository's visible policy.
- Official OSV 2.7.0: 6 locks, 1,448 package occurrences, four existing reviewed
  advisories, 0 malware findings, admission exit 0.
- Supplementary Semgrep production and secrets scans: 0 findings/errors.

## Shipping handoff

Merge only the exact signed final PR head after every required GitHub check is
green. Then run Codex Security against the exact merged-main SHA and confirm the
three high findings are absent without a new critical/high regression. This M1
does not publish crates or change versions; coordinated publication remains a
separate confirmed milestone after the remaining security batches and JWT HMAC
profile are integrated.

## Corrective handoff after PR #149

The PR #149 merged-main scan removed two original high findings but found that
SafeUrl still accepted carrier-grade/provider-metadata addresses and that
SafeRedirectUrl accepted a backslash network path. M1 therefore remains open.
The corrective branch extends the shared literal/resolver policy to conservative
public-unicast classification and canonicalizes redirects under a fixed HTTPS
origin. Final closure requires the corrective PR's exact-head CI and a clean
merged-main Codex Security result for both classes.

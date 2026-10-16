# High input boundaries M1 completion

## Delivered behavior

- Browser-ambiguous URI syntax and attribute delimiters fail closed; documented
  HTML sinks encode accepted values.
- Axum JSON and XML extractors enforce the configured limit while consuming body
  frames and share the same overflow/error mapping.
- SafeUrl uses the locked WHATWG parser, rejects ambiguous authorities and
  protected typed hosts, and returns the exact canonical value it classified.
  Resolved-address validation applies the same conservative public-unicast
  policy for caller-owned DNS pinning. SafeRedirectUrl resolves against one
  fixed HTTPS origin, rejects raw/encoded separator ambiguity, and retains a
  canonical relative reference.

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
- Corrective PR #150: all 33 exact-head checks passed; merged as validly signed,
  DCO-signed `6b99e38528ceba765a341ee54a6e2687e7607d4e`, with a tree byte-identical to
  reviewed signed head `b6ebb3b62e9ba0611355ea463cb661bc00dffdc4`.
- Exact merged-main Codex Security run
  `wfr_ba7e824e52f38743230cf3f9760ae39f61250e26e08e52cf854358c2cb7e3e51`:
  27 findings (10 medium, 17 low), 0 critical/high, and neither SafeUrl
  carrier-grade/provider-metadata nor SafeRedirectUrl normalization finding.
  Report SHA-256:
  `edcde530a644cc2408bd22276e873afca9c4a07d3c935b8184f722778885e50d`.

## Shipping handoff

M1 is merged and its exact merged-main scan is complete. This milestone does not
publish crates or change versions; coordinated publication remains a separate
confirmed milestone after the remaining security batches and JWT HMAC profile
are integrated.

## Corrective handoff after PR #149

The PR #149 merged-main scan removed two original high findings but found that
SafeUrl still accepted carrier-grade/provider-metadata addresses and that
SafeRedirectUrl accepted a backslash network path. The corrective branch
extended the shared literal/resolver policy to conservative public-unicast
classification and canonicalized redirects under a fixed HTTPS origin. PR #150
and the exact merged-main follow-up scan closed both classes; M1 is complete.

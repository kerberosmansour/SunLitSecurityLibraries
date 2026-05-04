# Security Policy

SunLit Security Libraries is security-sensitive infrastructure. Please report
vulnerabilities privately so maintainers can assess and fix them before public
disclosure.

## Reporting a vulnerability

Use GitHub's private advisory flow:

https://github.com/kerberosmansour/SunLitSecurityLibraries/security/advisories/new

If that is unavailable, contact the maintainer through the public GitHub profile
and include enough detail to reproduce the issue. Do not open a public issue for
vulnerabilities.

Useful reports include:

- Affected crate, version, feature flags, and platform.
- Minimal reproduction or proof of concept.
- Expected impact and attacker preconditions.
- Whether secrets, PII, authz boundaries, crypto, or supply-chain behavior are involved.

## Supported versions

| Version line | Supported |
|---|---|
| `main` | Yes |
| Latest published `0.x` release, once crates are published | Yes |
| Older unpublished snapshots | No |

Pre-1.0 APIs may still change, but security fixes for the latest public release
will be prioritized once the crates are published.

## Response targets

| Step | Target |
|---|---|
| Initial acknowledgement | 3 business days |
| Triage and severity assessment | 7 business days |
| Fix plan or status update | 14 business days |
| Coordinated disclosure | After a fix or agreed mitigation is available |

These are targets, not guarantees. Reports involving active exploitation,
credential exposure, auth bypass, or cryptographic breakage are handled first.

## Scope

In scope:

- Vulnerabilities in any crate under `crates/`.
- Unsafe defaults in examples, dev guides, or reference services that could
  reasonably be copied into production.
- CI, dependency, supply-chain, DAST, fuzzing, and release-process weaknesses.
- Sensitive data leakage in logs, errors, telemetry, or documentation.

Out of scope:

- Vulnerabilities in downstream applications that use these crates incorrectly.
- Denial-of-service against public project infrastructure such as GitHub Issues.
- Social engineering, spam, or physical attacks.
- Reports that require compromising third-party services not controlled by this project.

## Security defaults for contributors

- Keep public errors and logs free of secrets, credentials, PII, hostnames,
  stack traces, SQL text, and internal policy names.
- Preserve deny-by-default behavior for authorization, parsing, CORS, and unsafe
  URL handling.
- Feature-gate heavyweight or environment-specific integrations.
- Update `THREAT_MODEL.md` when a change introduces a new trust boundary,
  attacker capability, residual risk, or security invariant.
- Record verification evidence in the relevant runbook artifact under `docs/slo/`.
- Keep GitHub branch protection aligned with
  `docs/dev-guide/branch-protection.md` before public release.

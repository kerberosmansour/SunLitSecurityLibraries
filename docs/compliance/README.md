# Compliance Mappings

This directory holds per-framework compliance mappings for SunLitSecurityLibraries. The point of these documents is to let auditors check off vendor questionnaires without re-deriving the work from the codebase.

| Framework | Document | Status | Pin |
|---|---|---|---|
| ANSSI Rust Secure Coding Guidelines (FR) | [`anssi-rust.md`](./anssi-rust.md) | M1 (rule index bootstrapped; status placeholders pending M2) | ANSSI commit [`84e6ae18`](https://github.com/ANSSI-FR/rust-guide/tree/84e6ae181712c9ed797aeaf695c9965a13a1d5fa) (2026-04-07) |

OWASP Proactive Controls v3, OWASP MASVS, NIST 800-53, IEC 62443, and SOC 2 Type II mappings live in [`THREAT_MODEL.md`](../../THREAT_MODEL.md).

## Conventions

- Each mapping pins the upstream framework to a specific commit hash or published revision; refresh is a deliberate update, not silent drift.
- Each row carries a `Status` column from a fixed enum (typically `compliant | partial | waived | N/A`).
- "Compliant" rows carry an evidence pointer that resolves to a real artifact (file:line, test name, lint name, or doc path).
- "Waived" rows name a compensating control.
- "N/A" rows give an explicit reason.
- "unfilled" is a deliberate M1 placeholder during runbook bootstrap; it must be eliminated by M2.

## Related

- [Runbook](../slo/future/RUNBOOK-anssi-rust-compliance.md) — the SLO runbook driving the ANSSI mapping work.
- [Research dossier](../slo/research/anssi-rust-compliance/) — sources, family-count breakdown, EU regulation cross-walk.
- [`docs/dev-guide/anssi-mapping.md`](../dev-guide/anssi-mapping.md) — consumer-facing dev guide explaining how to use the mapping (added in M2).

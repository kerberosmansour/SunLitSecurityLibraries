# Changelog

All notable user-facing changes should be recorded here once the crates are
published.

This project follows the spirit of [Keep a Changelog](https://keepachangelog.com/)
and uses Cargo-compatible semantic versioning. Pre-1.0 releases may still make
breaking API changes, but security fixes and migration notes should be explicit.

## Unreleased

- The supply-chain CI lane now runs `cargo-geiger` (pinned to `0.13.0`) on
  every PR and uploads the JSON artifact (30-day retention). The advisory step
  surfaces transitive `unsafe` usage in the dependency tree; deltas are
  visible to reviewers on the PR via artifact diff. Local parity is
  available via `bash scripts/audit.sh` (or `pwsh scripts/audit.ps1`).
  The current measured baseline (root = `secure_reference_service`,
  `--all-features`) is **22 636 transitive unsafe expressions used / 48 192
  available**; SunLit crates contribute zero. Threshold = baseline + 10 %
  headroom. Promotion of the threshold to a blocking gate is a separate
  future runbook. See `docs/dev-guide/unsafe-budget.md`.
- All workspace crates are now `#![forbid(unsafe_code)]` (added to
  `secure_smoke_service`; the other 13 crates already had the attribute). The
  posture is regression-tested by `crates/security_core/tests/no_unsafe_code.rs`
  — any future removal fails the build with a named-crate error. A companion
  scan also asserts no `unsafe ` keyword appears anywhere in `crates/*/src/`.
- Added public open-source governance files: license, notice, trademarks,
  contributing guide, security policy, code of conduct, issue templates, and PR
  template.
- Normalized runbooks and milestone artifacts under `docs/slo/`.

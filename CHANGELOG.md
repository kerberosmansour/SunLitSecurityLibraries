# Changelog

All notable user-facing changes should be recorded here once the crates are
published.

This project follows the spirit of [Keep a Changelog](https://keepachangelog.com/)
and uses Cargo-compatible semantic versioning. Pre-1.0 releases may still make
breaking API changes, but security fixes and migration notes should be explicit.

## Unreleased

- All workspace crates are now `#![forbid(unsafe_code)]` (added to
  `secure_smoke_service`; the other 13 crates already had the attribute). The
  posture is regression-tested by `crates/security_core/tests/no_unsafe_code.rs`
  — any future removal fails the build with a named-crate error. A companion
  scan also asserts no `unsafe ` keyword appears anywhere in `crates/*/src/`.
  See `docs/dev-guide/unsafe-budget.md` for the posture and the planned
  `cargo-geiger` transitive-unsafe number (next milestone).
- Added public open-source governance files: license, notice, trademarks,
  contributing guide, security policy, code of conduct, issue templates, and PR
  template.
- Normalized runbooks and milestone artifacts under `docs/slo/`.

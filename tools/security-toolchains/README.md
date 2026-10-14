# Scanned security toolchains

The security tools are dependencies too. Their resolved locks are scanned with
OSV before their source or build scripts execute. Source archive SHA-256 values
match crates.io metadata; VCS commits were checked in each official GitHub repo.
`recipes.json` fixes source and lockfile integrity, then
`scripts/install-security-tool.py` verifies the admission report and builds only
with `--locked`. No floating installer or hidden transitive refresh is allowed.

- cargo-audit 0.22.2 and cargo-deny 0.20.2 use compatible, frozen dependency refreshes.
  kstring is held at 2.0.2 because 2.0.3–2.0.5 require Rust 1.96 while the
  locally verified compiler is Rust 1.95. The held version scans clean.
- kani-verifier 0.68.0 uses its scanned frozen graph.
- cargo-vet 0.10.2 keeps its audit evaluation code. Its original reqwest 0.11 graph
  retains unpatched TLS/HTTP dependencies. A **manifest-only overlay** pins
  reqwest 0.12.28 and indicatif 0.18.3, removing that legacy network graph and the
  unmaintained number_prefix dependency. This is a locally built dependency
  overlay, not an upstream cargo-vet release or an upstream audit endorsement.

The latest cargo-geiger 0.14.0 still has unpatched dependencies. Its optional,
advisory-only inventory is parked; no waiver is added to run it. Existing unsafe
attestation, native feature/build guards, SAST and bounded Kani checks remain.
Re-enable only with an admitted graph and a reviewed tool update.

Semgrep 1.180.0 uses a fully resolved Python 3.11/Linux x86_64, hash-pinned,
wheel-only requirements graph. Pip resolves/downloads metadata without package
execution; installation uses --require-hashes --no-deps --only-binary. The
requirements lock participates in admission before scanning source.

Library advisory exceptions are scoped only to the root Cargo.lock. They cannot
suppress a vulnerability in these toolchains. All graphs are part of the scan
inventory and receipt. Do not edit recipes/locks to bypass a finding; resolve,
scan and review a concrete update first.

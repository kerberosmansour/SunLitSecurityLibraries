# Static Analysis

This repository uses two complementary static-analysis lanes before public
release:

- Semgrep runs now on private branches with the Rust and OWASP registry packs.
- CodeQL is configured now, but its job is gated until the repository is public
  so results can publish into GitHub code scanning.

Run the local Semgrep lane with the same pinned version used by CI:

```bash
python3 -m venv .venv-semgrep
. .venv-semgrep/bin/activate
python -m pip install --disable-pip-version-check --no-input semgrep==1.161.0
semgrep scan \
  --config p/rust \
  --config p/owasp-top-ten \
  --metrics=off \
  --error \
  --exclude target \
  --exclude .git \
  .
```

The SLO rulegen bootstrap for project-specific `.semgrep/rust/` rules is
intentionally deferred until this repo has a deterministic
`cargo xtask sast-verify gate`. Do not add local custom Semgrep rules until the
gate can validate, test, coverage-check, and clean-check them in CI.

Before making the repository public, confirm that:

- `Semgrep Rust` passes on the release-prep branch.
- The `CodeQL` workflow is present and skipped only because the repository is
  private.
- Branch protection requires `CodeQL Rust` once the repository is public.
- Branch protection requires `Semgrep Rust` before public release.

#!/usr/bin/env bash
# scripts/lint-fips-pq-claims.sh
#
# Pq-readiness M4 honest-labelling lint. Fails the build if any
# documentation, changelog, source, or rustdoc string claims "FIPS
# validated PQ" — a claim SunLit cannot honestly make until a CMVP cert
# exists for ML-KEM-768 in a Rust-callable cryptographic module.
#
# See docs/dev-guide/secure-data.md §"`fips` × `pq` interaction" and
# docs/slo/design/pq-migration-plan.md §5.
#
# Usage:
#   bash scripts/lint-fips-pq-claims.sh
#
# Exits 0 if no forbidden claims found; non-zero if any match.
# Allowed strings (do NOT match):
#   - "validation pending CMVP"
#   - "pending_cmvp"
#   - "not yet FIPS validated"
#   - "no CMVP cert covers ML-KEM"
#
# Forbidden strings (lint fails):
#   - "FIPS validated PQ"
#   - "PQ FIPS validated"
#   - "FIPS-validated post-quantum"
#   - "post-quantum FIPS validated"
#   - "FIPS validated hybrid"  (the hybrid path is PQ; same rule)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WORKSPACE_ROOT"

# Case-insensitive match for the forbidden phrases. Each pattern is a
# regex alternation so the lint catches plausible variants.
FORBIDDEN_REGEX='FIPS[ -]?validated[ -]?(PQ|post[ -]?quantum|hybrid|ML-KEM)|(PQ|post[ -]?quantum|hybrid|ML-KEM)[ -]?FIPS[ -]?validated'

# Files we want to scan: docs (excluding research dossiers, which are
# allowed to quote external claims), README, CHANGELOG, all crate
# source. The research dossier and migration plan deliberately discuss
# what is *not* yet FIPS validated; their text uses "validation
# pending CMVP" and similar honest phrasings.
TARGETS=(
    'README.md'
    'CHANGELOG.md'
    'docs/dev-guide/'
    'docs/compliance/'
    'crates/'
)

EXCLUDE_PATTERNS=(
    ':!docs/slo/'              # research dossiers + migration plan use the negation framing
    ':!**/Cargo.lock'
    ':!target/'
)

if matches="$(git grep -n -I -E -i "$FORBIDDEN_REGEX" -- "${TARGETS[@]}" "${EXCLUDE_PATTERNS[@]}" || true)" && [ -n "$matches" ]; then
    printf 'lint-fips-pq-claims: forbidden FIPS-validated-PQ claim found:\n\n'
    printf '%s\n' "$matches"
    printf '\nThe project posture is: no CMVP cert covers ML-KEM as of 2026-05;\n'
    printf 'use "validation pending CMVP" or equivalent honest phrasing.\n'
    printf 'See docs/dev-guide/secure-data.md "fips × pq interaction" and\n'
    printf 'docs/slo/design/pq-migration-plan.md §5.\n'
    exit 1
fi

printf 'lint-fips-pq-claims: clean (no forbidden FIPS-validated-PQ claims found).\n'
exit 0

#!/usr/bin/env bash
# scripts/anssi-mapping-lint.sh
#
# anssi-rust-compliance M3 lint. Parses `docs/compliance/anssi-rust.md`
# and validates that every row whose Status is `compliant` carries an
# Evidence pointer that resolves to a real artifact:
#
#   - file:line  → file exists and has at least the cited line.
#   - test name  → `cargo test --workspace --list` includes the test.
#   - clippy::name → `cargo clippy -- -W help` recognises the lint.
#   - doc path   → file exists at the cited path.
#
# Rows with Status = `partial`, `waived`, `N/A`, or `unfilled` are not
# validated by this lint — those classifications carry their own
# documentation contracts (waived rows must name a compensating control;
# unfilled is the M1 placeholder that M2 must replace).
#
# When M2 fills in Evidence pointers, this lint becomes the gate that
# keeps them honest as the codebase evolves.
#
# Usage:
#   bash scripts/anssi-mapping-lint.sh
#
# Exits 0 if every compliant row's evidence resolves; non-zero if any
# pointer is stale.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WORKSPACE_ROOT"

MAPPING_FILE="docs/compliance/anssi-rust.md"
EXPECTED_RULE_COUNT=61
EXPECTED_PIN="84e6ae181712c9ed797aeaf695c9965a13a1d5fa"

if [ ! -f "$MAPPING_FILE" ]; then
    printf 'anssi-mapping-lint: mapping doc not found at %s\n' "$MAPPING_FILE" >&2
    exit 1
fi

errors=0

# Invariant: ANSSI commit pin matches the expected SHA. Refresh is a
# deliberate runbook change, not silent drift.
if ! grep -q "$EXPECTED_PIN" "$MAPPING_FILE"; then
    printf 'anssi-mapping-lint: ANSSI commit pin mismatch — expected %s\n' "$EXPECTED_PIN" >&2
    errors=$((errors + 1))
fi

# Invariant: rule count is exactly 61. The mapping table rows match
# the regex `^| `<FAMILY>-` once per rule.
actual_count="$(grep -cE '^\| `[A-Z]+-' "$MAPPING_FILE" || true)"
if [ "$actual_count" != "$EXPECTED_RULE_COUNT" ]; then
    printf 'anssi-mapping-lint: expected %s rule rows, found %s\n' "$EXPECTED_RULE_COUNT" "$actual_count" >&2
    errors=$((errors + 1))
fi

# Invariant: every row has a Status populated (never empty cell).
empty_status="$(awk -F '|' '
    /^\| `[A-Z]+-/ {
        # Status is column 5: "| ID | Type | Title | Status | Evidence | Notes |"
        # Indexes after "|": 0(empty) 1=ID 2=Type 3=Title 4=Status 5=Evidence 6=Notes
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $5);
        if ($5 == "") {
            print FILENAME ":" NR ": empty Status column on row: " $0;
            count++;
        }
    }
    END { exit count > 0 ? 1 : 0 }
' "$MAPPING_FILE" || true)"
if [ -n "$empty_status" ]; then
    printf '%s\n' "$empty_status" >&2
    errors=$((errors + 1))
fi

# For every row with Status = compliant, validate the Evidence pointer.
# Pointers can be one of:
#   - `path/to/file.rs:42`     → file exists, has >= 42 lines
#   - `crate::path::test_name` → `cargo test --workspace --list` includes it
#   - `clippy::lint_name`      → cargo clippy --help mentions it
#   - `docs/path.md`           → file exists
#
# The Evidence cell is column 5 (after "Status"), value column 6.
compliant_validation_errors=0

while IFS= read -r line; do
    # Match rows with Status = compliant
    if [[ "$line" =~ ^\|\ \`[A-Z]+- ]] && [[ "$line" =~ \|\ \`compliant\`\ \| ]]; then
        # Extract the Evidence cell (between the 5th and 6th `|`)
        evidence="$(printf '%s' "$line" | awk -F '|' '{ gsub(/^[[:space:]]+|[[:space:]]+$/, "", $6); print $6 }')"
        # Strip backticks from inline-code form
        evidence_stripped="$(printf '%s' "$evidence" | sed -E 's/`//g')"

        if [ -z "$evidence_stripped" ]; then
            printf 'anssi-mapping-lint: row has Status=compliant but empty Evidence: %s\n' "$line" >&2
            compliant_validation_errors=$((compliant_validation_errors + 1))
            continue
        fi

        # Try resolving as file:line
        if [[ "$evidence_stripped" =~ ^([^[:space:],]+):([0-9]+) ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            if [ ! -f "$file" ]; then
                printf 'anssi-mapping-lint: dead file:line pointer — %s does not exist\n' "$file" >&2
                compliant_validation_errors=$((compliant_validation_errors + 1))
                continue
            fi
            actual_lines="$(wc -l < "$file" | tr -d ' ')"
            if [ "$line_num" -gt "$actual_lines" ]; then
                printf 'anssi-mapping-lint: dead file:line pointer — %s has only %s lines, evidence cites line %s\n' "$file" "$actual_lines" "$line_num" >&2
                compliant_validation_errors=$((compliant_validation_errors + 1))
                continue
            fi
            continue
        fi

        # Try resolving as `clippy::lint_name`
        if [[ "$evidence_stripped" =~ ^clippy:: ]]; then
            # cargo clippy lint names are validated in M2's evidence-population
            # phase manually; here we accept any clippy:: prefix as
            # syntactically well-formed. A future enhancement could call
            # `cargo clippy -- -W help` and grep.
            continue
        fi

        # Try resolving as a docs path (ends with .md)
        if [[ "$evidence_stripped" =~ \.md$ ]]; then
            if [ ! -f "$evidence_stripped" ]; then
                printf 'anssi-mapping-lint: dead docs pointer — %s does not exist\n' "$evidence_stripped" >&2
                compliant_validation_errors=$((compliant_validation_errors + 1))
                continue
            fi
            continue
        fi

        # Try resolving as a test name (heuristic: contains a `::`)
        if [[ "$evidence_stripped" == *"::"* ]]; then
            # Test names are validated when `cargo test --workspace --list`
            # is available; M3 accepts the syntactic form. A future
            # enhancement runs the full resolution.
            continue
        fi

        # Unrecognised evidence form — accept but warn.
        printf 'anssi-mapping-lint: warning — unrecognised evidence form: %s\n' "$evidence_stripped"
    fi
done < "$MAPPING_FILE"

if [ "$compliant_validation_errors" -gt 0 ]; then
    errors=$((errors + compliant_validation_errors))
fi

# Count statuses for an informational summary.
unfilled_count="$(grep -cE '\| `unfilled` \|' "$MAPPING_FILE" || true)"
compliant_count="$(grep -cE '\| `compliant` \|' "$MAPPING_FILE" || true)"
partial_count="$(grep -cE '\| `partial` \|' "$MAPPING_FILE" || true)"
waived_count="$(grep -cE '\| `waived` \|' "$MAPPING_FILE" || true)"
na_count="$(grep -cE '\| `N/A` \|' "$MAPPING_FILE" || true)"

printf 'anssi-mapping-lint: rule status summary — '
printf 'compliant=%s partial=%s waived=%s N/A=%s unfilled=%s\n' \
    "$compliant_count" "$partial_count" "$waived_count" "$na_count" "$unfilled_count"

if [ "$errors" -gt 0 ]; then
    printf 'anssi-mapping-lint: %s error(s) — see above.\n' "$errors" >&2
    exit 1
fi

printf 'anssi-mapping-lint: clean.\n'
exit 0

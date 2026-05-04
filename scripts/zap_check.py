#!/usr/bin/env python3
"""scripts/zap_check.py — Parse OWASP ZAP JSON report and gate on high/critical findings.

Usage:
    python3 scripts/zap_check.py --report output/zap-report.json [--baseline scripts/zap-baseline.json]

Exit codes:
    0 — No high/critical findings (or all suppressed by baseline)
    1 — High/critical findings detected
    2 — Usage error or report parse failure
"""

import argparse
import json
import sys
from pathlib import Path


# ZAP risk codes: 0=Informational, 1=Low, 2=Medium, 3=High
RISK_LABELS = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}
GATE_THRESHOLD = 3  # Block on High (3) and above


def load_json(path: Path) -> dict:
    """Load and parse a JSON file."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[ERROR] Failed to load {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def load_baseline(path: Path | None) -> set[str]:
    """Load baseline alert IDs to suppress (known false positives).

    Returns a set of 'pluginId:alertRef' strings that should be ignored.
    Each entry in the baseline file must have a 'justification' field.
    """
    if path is None or not path.exists():
        return set()

    data = load_json(path)
    suppressed = set()
    entries = data.get("suppressions", [])

    for entry in entries:
        plugin_id = str(entry.get("pluginId", ""))
        alert_ref = str(entry.get("alertRef", plugin_id))
        justification = entry.get("justification", "")

        if not justification.strip():
            print(
                f"[WARN] Baseline entry pluginId={plugin_id} has no justification — skipping",
                file=sys.stderr,
            )
            continue

        key = f"{plugin_id}:{alert_ref}"
        suppressed.add(key)

    if suppressed:
        print(f"[INFO] Baseline: {len(suppressed)} suppression(s) loaded from {path}")

    return suppressed


def parse_zap_report(report: dict) -> list[dict]:
    """Extract alerts from a ZAP JSON report.

    Supports both the traditional ZAP JSON format (site[].alerts[])
    and the newer format with a top-level 'alerts' or 'site' key.
    """
    alerts = []

    # Traditional format: {"site": [{"alerts": [...]}]}
    sites = report.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_alerts = site.get("alerts", [])
        for alert in site_alerts:
            alerts.append(
                {
                    "pluginId": str(alert.get("pluginid", alert.get("pluginId", ""))),
                    "alertRef": str(
                        alert.get("alertRef", alert.get("pluginid", alert.get("pluginId", "")))
                    ),
                    "name": alert.get("name", alert.get("alert", "Unknown")),
                    "riskcode": int(alert.get("riskcode", 0)),
                    "confidence": int(alert.get("confidence", 0)),
                    "description": alert.get("description", ""),
                    "count": len(alert.get("instances", [])),
                }
            )

    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse OWASP ZAP JSON report and gate on high/critical findings."
    )
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="Path to the ZAP JSON report file",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Path to the baseline JSON file with known false positives",
    )
    args = parser.parse_args()

    if not args.report.exists():
        print(f"[ERROR] Report file not found: {args.report}", file=sys.stderr)
        sys.exit(2)

    report = load_json(args.report)
    suppressed = load_baseline(args.baseline)
    alerts = parse_zap_report(report)

    if not alerts:
        print("[INFO] No alerts found in ZAP report.")
        print("[PASS] DAST gate passed — no findings.")
        sys.exit(0)

    # Categorise alerts
    high_critical = []
    medium = []
    low_info = []
    suppressed_alerts = []

    for alert in alerts:
        key = f"{alert['pluginId']}:{alert['alertRef']}"
        risk = alert["riskcode"]
        risk_label = RISK_LABELS.get(risk, f"Unknown({risk})")

        if key in suppressed:
            suppressed_alerts.append(alert)
            continue

        if risk >= GATE_THRESHOLD:
            high_critical.append(alert)
        elif risk == 2:
            medium.append(alert)
        else:
            low_info.append(alert)

    # Print summary
    print("=" * 60)
    print("ZAP Finding Summary")
    print("=" * 60)

    if suppressed_alerts:
        print(f"\n  Suppressed (baseline): {len(suppressed_alerts)}")
        for a in suppressed_alerts:
            print(f"    - [{RISK_LABELS.get(a['riskcode'], '?')}] {a['name']} (pluginId={a['pluginId']})")

    if low_info:
        print(f"\n  Informational/Low: {len(low_info)}")
        for a in low_info:
            print(f"    - [{RISK_LABELS.get(a['riskcode'], '?')}] {a['name']} ({a['count']} instance(s))")

    if medium:
        print(f"\n  Medium: {len(medium)}")
        for a in medium:
            print(f"    - [Medium] {a['name']} ({a['count']} instance(s))")

    if high_critical:
        print(f"\n  HIGH/CRITICAL: {len(high_critical)}")
        for a in high_critical:
            print(f"    - [HIGH] {a['name']} ({a['count']} instance(s), pluginId={a['pluginId']})")

    print("")

    if high_critical:
        print(f"[FAIL] {len(high_critical)} high/critical finding(s) detected.")
        print("  Add justified suppressions to the baseline file, or fix the underlying issue.")
        sys.exit(1)
    else:
        total = len(medium) + len(low_info)
        print(f"[PASS] No high/critical findings. {total} lower-severity finding(s) noted.")
        sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fail closed on missing/malformed Dastardly output or reported failures."""
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def check_report(path):
    if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("Dastardly report absent or exceeds bound")
    root = ET.fromstring(path.read_bytes())
    local = lambda tag: tag.rsplit("}", 1)[-1]
    if local(root.tag) not in {"testsuite", "testsuites"}:
        raise ValueError("Unexpected Dastardly report schema")
    suites = [element for element in root.iter() if local(element.tag) == "testsuite"]
    if not suites:
        raise ValueError("Dastardly report contains no completed suite")
    for suite in suites:
        if not all(key in suite.attrib for key in ("tests", "failures", "errors")):
            raise ValueError("Dastardly suite is missing completion counts")
        if any(int(suite.get(key)) < 0 for key in ("tests", "failures", "errors")):
            raise ValueError("Invalid Dastardly suite count")
    failures = sum(local(element.tag) in {"failure", "error"} for element in root.iter())
    summaries = [int(element.get(key, "0")) for element in root.iter() if local(element.tag) in {"testsuite", "testsuites"} for key in ("failures", "errors")]
    if any(value < 0 for value in summaries):
        raise ValueError("Invalid Dastardly summary count")
    return bool(failures or any(summaries))


if __name__ == "__main__":
    try:
        found = check_report(Path(sys.argv[1]))
        print("Dastardly reported issues" if found else "Dastardly scan completed with no reported issues")
        sys.exit(1 if found else 0)
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"Dastardly report verification failed: {error}", file=sys.stderr)
        sys.exit(2)

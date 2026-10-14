#!/usr/bin/env python3
"""Inspect an isolated normal/build graph without executing dependency code."""
import argparse
import importlib.util
import hashlib
import re
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/jwt-hmac-consumer"


def inspect_graph():
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--manifest-path", str(FIXTURE / "Cargo.toml"),
        "--format-version", "1", "--locked",
    ], cwd=ROOT, timeout=60))
    resolved = metadata["resolve"]
    nodes = {node["id"]: node for node in resolved["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    pending = [resolved["root"]]
    reached = set()
    while pending:
        identity = pending.pop()
        if identity in reached:
            continue
        reached.add(identity)
        for dependency in nodes[identity]["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    forbidden = [packages[identity]["name"] for identity in reached
                 if packages[identity]["name"] == "rsa"]
    root_lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    candidate = tomllib.loads((FIXTURE / "Cargo.lock").read_text())
    admitted = {(p["name"], p["version"], p["source"], p["checksum"])
                for p in root_lock["package"] if "source" in p}
    external = {(p["name"], p["version"], p["source"], p["checksum"])
                for p in candidate["package"] if "source" in p}
    if external - admitted:
        raise ValueError("Fixture contains unreviewed external identity/checksum")
    if forbidden:
        raise ValueError("Reduced normal/build consumer graph includes rsa")
    return {"normalBuildPackages": len(reached), "rsaPackages": 0,
            "externalIdentitiesAreRootSubset": True,
            "graphInspectionExecutedNoBuildScripts": True}


def admit_all_locks(output):
    # Generic admission excludes deliberately vulnerable fixture directories.
    # This exact executable consumer is not a vulnerable fixture: graph review
    # must pass before admitting its lock alongside every production/tool lock.
    path = FIXTURE / "Cargo.lock"
    if path.is_symlink() or not path.is_file() or any(parent.is_symlink() for parent in (FIXTURE, FIXTURE.parent)):
        raise ValueError("Consumer lock must be an owned real repository file")
    if ROOT not in path.resolve().parents:
        raise ValueError("Consumer lock escaped repository")
    spec = importlib.util.spec_from_file_location("hmac_osv_gate", ROOT / "scripts/osv-dependency-gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    ordinary_locks = gate.lockfiles()
    gate.lockfiles = lambda: sorted({*ordinary_locks, path})
    # Reuse all checksum, inventory, native guard, exception and snapshot checks.
    # Root exceptions stay source-scoped and cannot admit consumer advisories.
    output.with_suffix(".receipt.json").unlink(missing_ok=True)
    previous = sys.argv
    try:
        sys.argv = [str(ROOT / "scripts/osv-dependency-gate.py"), "--output", str(output)]
        return gate.main()
    finally:
        sys.argv = previous


def prove_kani(output, report, receipt):
    admission = json.loads(receipt.read_text())
    if admission.get("admissionExitCode") != 0 or admission.get("reportSHA256") != hashlib.sha256(report.read_bytes()).hexdigest():
        raise ValueError("Kani needs successful unchanged all-lock admission")
    expected = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in [*ordinary_locks_for_proof(), FIXTURE / "Cargo.lock"]}
    actual = {item["path"]: item["sha256"] for item in admission["lockfiles"]}
    if actual != expected or len(admission["lockfiles"]) != len(expected):
        raise ValueError("Kani admission omits, duplicates or changed a root/tool/consumer lock")
    if any(item.get("sourcePath") != str(ROOT / item["path"]) for item in admission["lockfiles"]):
        raise ValueError("Kani admission belongs to another source checkout")
    source = ROOT / "crates/secure_identity/src/jwt_hmac.rs"
    if source.is_symlink() or ROOT not in source.resolve().parents or any((ROOT / parent).is_symlink() for parent in source.relative_to(ROOT).parents if parent != Path(".")):
        raise ValueError("Kani source must be a real target-crate file")
    original = source.read_text()
    weak_key = "length >= self.bytes() && length <= MAX_KEY_BYTES"
    if original.count(weak_key) != 1:
        raise ValueError("Expected exact key policy mutation target")
    mutant = original.replace(weak_key, "length <= MAX_KEY_BYTES")
    pattern = r"(fn message_fits\(self, length: usize\) -> bool \{).*?(\n    \})"
    mutant, replacements = re.subn(pattern, r"\1\n        length <= MAX_JWT_BYTES\2", mutant, count=1, flags=re.S)
    if replacements != 1:
        raise ValueError("Expected exact complete-token policy mutation target")
    command = [sys.executable, str(ROOT / "scripts/run-security-tool.py"), "--report", str(report),
               "--receipt", str(receipt), "kani-verifier", "--", "-p", "secure_identity",
               "--no-default-features", "--features", "jwt-hmac", "--output-format", "old"]
    names = ["key_acceptance_has_required_length_and_allocation_bounds", "signing_size_never_wraps_or_exceeds_complete_token_bound"]
    def run(label, expected_return, expected_summary):
        log = output.with_name(output.stem + "." + label + ".log")
        with log.open("w") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=900, shell=False)
        text = log.read_text()
        if (result.returncode != expected_return or "Kani Rust Verifier 0.68.0" not in text
                or expected_summary not in text or not all("Checking harness jwt_hmac::proofs::" + name in text for name in names)):
            raise ValueError("Kani " + label + " did not positively classify both expected harnesses; inspect saved log")
    try:
        source.write_text(mutant)
        run("red", 1, "Complete - 0 successfully verified harnesses, 2 failures, 2 total.")
    finally:
        source.write_text(original)
    run("green", 0, "Complete - 2 successfully verified harnesses, 0 failures, 2 total.")
    if source.read_text() != original:
        raise ValueError("Kani mutation did not restore source")
    return {"version": "0.68.0", "mutantFailures": 2, "provedHarnesses": 2,
            "kinds": 3, "lengthDomain": "all usize values on x86_64", "noHeapOrLoopBound": True,
            "stubs": [], "concurrencyOrCryptographyProved": False, "sourceRestored": True}


def ordinary_locks_for_proof():
    spec = importlib.util.spec_from_file_location("proof_osv_gate", ROOT / "scripts/osv-dependency-gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate.lockfiles()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--admit", action="store_true", help="Run unchanged pinned OSV core over root/tool/consumer locks before builds")
    parser.add_argument("--prove-kani", action="store_true", help="Run exact red/green bounded kernels using the approved installed CI tool")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"status": "failed"}, indent=2) + "\n")
    result = inspect_graph()
    if args.prove_kani:
        if args.admit or args.report is None or args.receipt is None:
            raise ValueError("Kani requires separate successful report/receipt, not implicit admission")
        proof = prove_kani(args.output, args.report, args.receipt)
        args.output.write_text(json.dumps({"status": "pass", **proof}, indent=2) + "\n")
        print("Both Kani policy mutants fail; original kernels prove at stated bounds")
        return 0
    if args.admit:
        code = admit_all_locks(args.output)
        if code:
            return code
        graph_output = args.output.with_name(args.output.stem + ".graph.json")
    else:
        graph_output = args.output
    graph_output.write_text(json.dumps({"status": "pass", **result}, indent=2) + "\n")
    print("Reduced normal/build graph excludes rsa and preserves exact external identities")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"JWT profile graph check failed: {error}", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Inspect an isolated normal/build graph without executing dependency code."""
import argparse
import copy
import importlib.util
import hashlib
import re
import json
from pathlib import Path, PureWindowsPath
import os
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/jwt-hmac-consumer"

POLICIES = {
    "key_acceptance_has_required_length_and_allocation_bounds": "assertion failed: kind.key_fits(length) == length >= required && length <= 1024",
    "signing_size_never_wraps_or_exceeds_complete_token_bound": "assertion failed: kind.message_fits(length) == complete.is_some_and(|total| total <= 65536)",
}
KEY_COVERS = ["JHK_KEY_ZERO", "JHK_KEY_256_MIN", "JHK_KEY_384_MIN", "JHK_KEY_512_MIN",
              "JHK_KEY_MAX", "JHK_KEY_OVER_MAX", "JHK_KEY_USIZE_MAX"]
MESSAGE_COVERS = ["JHK_MESSAGE_ZERO", "JHK_MESSAGE_256_MAX", "JHK_MESSAGE_384_MAX",
                  "JHK_MESSAGE_512_MAX", "JHK_MESSAGE_OVER_MAX", "JHK_MESSAGE_USIZE_MAX"]


def owned_path(path):
    if (path.is_symlink() or not path.is_file() or ROOT not in path.resolve().parents
            or any((ROOT / parent).is_symlink() for parent in path.relative_to(ROOT).parents if parent != Path("."))):
        raise ValueError("Admission/proof path must be a real owned repository file")
    return path


def consumer_lock():
    owned_path(FIXTURE / "Cargo.toml")
    return owned_path(FIXTURE / "Cargo.lock")


def valid_kani_output(text, label, returncode):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    summary = "Complete - " + ("0 successfully verified harnesses, 2 failures, 2 total." if label == "red" else "2 successfully verified harnesses, 0 failures, 2 total.")
    lines = text.splitlines()
    if (label not in {"red", "green"} or returncode != (1 if label == "red" else 0)
            or [line for line in lines if line.startswith("Kani Rust Verifier")] != ["Kani Rust Verifier 0.68.0 (cargo plugin)"]
            or [line for line in lines if line.startswith("Complete -")] != [summary]
            or not text.rstrip().endswith(summary)):
        return False
    expected = {"jwt_hmac::proofs::" + name for name in POLICIES}
    headers = re.findall(r"(?m)^Checking harness ([^\n]+)\.\.\.$", text)
    if len(headers) != 2 or set(headers) != expected:
        return False
    blocks = re.findall(r"(?ms)^Checking harness ([^\n]+)\.\.\.\n(.*?)(?=^Checking harness |^Manual Harness Summary:|^Complete -|\Z)", text)
    if len(blocks) != 2:
        return False
    counted = 0
    for harness, body in blocks:
        checks = re.findall(r'(?m)^Check (\d+): ([^\n]+)\n[ \t]+- Status: (\w+)\n[ \t]+- Description: "([^\n]*)"', body)
        counted += len(checks)
        if (not checks or len(checks) != len(re.findall(r"(?m)^Check ", body))
                or [int(item[0]) for item in checks] != list(range(1, len(checks) + 1))
                or len({item[1] for item in checks}) != len(checks)):
            return False
        description = POLICIES[harness.removeprefix("jwt_hmac::proofs::")]
        policy = [item for item in checks if item[3] == description]
        required = "FAILURE" if label == "red" else "SUCCESS"
        if len(policy) != 1 or policy[0][2] != required or not re.fullmatch(re.escape(harness) + r"\.assertion\.\d+", policy[0][1]):
            return False
        allowed = {"SUCCESS", "SATISFIED", "UNREACHABLE"}
        if any(item[2] not in allowed and item != policy[0] for item in checks):
            return False
        if label == "green":
            covers = [item for item in checks if ".cover." in item[1]]
            wanted = KEY_COVERS if harness.endswith("allocation_bounds") else MESSAGE_COVERS
            labels = [item[3].removeprefix("cover condition: ") for item in covers]
            if (len(covers) != len(wanted) or set(labels) != set(wanted)
                    or any(item[2] != "SATISFIED" or not re.fullmatch(re.escape(harness) + r"\.cover\.\d+", item[1]) for item in covers)):
                return False
    return counted == len(re.findall(r"(?m)^Check ", text))


def proof_parser_self_test():
    # Synthetic syntax fixtures only, never a verifier/proof result.
    def fixture(label):
        result = "Kani Rust Verifier 0.68.0 (cargo plugin)\n"
        for index, (name, description) in enumerate(POLICIES.items()):
            harness = "jwt_hmac::proofs::" + name
            result += "Checking harness " + harness + "...\n"
            status = "FAILURE" if label == "red" else "SUCCESS"
            result += f'Check 1: {harness}.assertion.1\n\t - Status: {status}\n\t - Description: "{description}"\n'
            for number, cover in enumerate(KEY_COVERS if index == 0 else MESSAGE_COVERS, 2):
                result += f'Check {number}: {harness}.cover.{number}\n\t - Status: SATISFIED\n\t - Description: "{cover}"\n'
        return result + "Complete - " + ("0 successfully verified harnesses, 2 failures, 2 total." if label == "red" else "2 successfully verified harnesses, 0 failures, 2 total.") + "\n"
    good = fixture("green")
    if not valid_kani_output(good, "green", 0) or not valid_kani_output(fixture("red"), "red", 1):
        raise ValueError("Canonical synthetic Kani syntax fixtures rejected")
    name = next(iter(POLICIES))
    duplicate = f'Check 9: jwt_hmac::proofs::{name}.assertion.1\n\t - Status: FAILURE\n\t - Description: "{POLICIES[name]}"\n'
    hostile = [good.replace("Checking harness jwt_hmac::proofs::signing", duplicate + "Checking harness jwt_hmac::proofs::signing", 1),
               good.replace("JHK_KEY_ZERO", "JHK_KEY_ZERO JHK_KEY_256_MIN", 1),
               good.replace("JHK_KEY_ZERO", "JHK_KEY_256_MIN", 1),
               good.replace("Status: SATISFIED", "Status: UNDETERMINED", 1),
               good.replace("Status: SUCCESS", "Status: UNREACHABLE", 1),
               good + good.splitlines()[-1] + "\n",
               "Kani Rust Verifier 0.68.0 (cargo plugin)\n" + good,
               good.replace(" - Status: SATISFIED", " - Status SATISFIED", 1),
               good + duplicate]
    if any(valid_kani_output(text, "green", 0) for text in hostile) or valid_kani_output(good, "green", 1):
        raise ValueError("Kani parser accepted duplicate/mixed/missing/unsupported result")
    return {"syntheticParserNegativeCases": len(hostile) + 1}


def ownership_self_test():
    if os.name == "nt":
        return {"ownershipSymlinkCases": "POSIX fixture; guard remains enabled on Windows"}
    cache = ROOT / ".cache"
    if cache.is_symlink():
        raise ValueError("Ownership regression cache must be real")
    cache.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="jwt-hmac-ownership-", dir=cache) as directory:
        folder = Path(directory)
        actual = folder / "owned"
        actual.mkdir()
        lock = actual / "Cargo.lock"
        lock.write_text("same bytes\n")
        owned_path(lock)
        alias = folder / "alias.lock"
        alias.symlink_to(lock)
        link = folder / "alias-directory"
        link.symlink_to(actual, target_is_directory=True)
        for path in [alias, link / "Cargo.lock"]:
            try:
                owned_path(path)
            except ValueError:
                continue
            raise ValueError("Ownership regression admitted same-byte alias")
    return {"ownershipSymlinkCases": 2}


def scanner_inventory(validator, report, paths, windows):
    # OSV's Go path serialization uses forward slashes on Windows. Only accept
    # the exact requested path's slash spelling; never resolve arbitrary paths,
    # fold case, accept relative paths or modify the saved raw scanner report.
    checked = copy.deepcopy(report)
    if windows and isinstance(checked, dict) and isinstance(checked.get("results"), list):
        aliases = {path.as_posix(): str(path) for path in paths}
        for entry in checked["results"]:
            if isinstance(entry, dict) and isinstance(entry.get("source"), dict):
                reported = entry["source"].get("path")
                if isinstance(reported, str) and reported in aliases:
                    entry["source"]["path"] = aliases[reported]
    return validator(checked, paths)


def inventory_self_test():
    spec = importlib.util.spec_from_file_location("inventory_osv_gate", ROOT / "scripts/osv-dependency-gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    path = PureWindowsPath("D:/a/repo/fixtures/jwt-hmac-consumer/Cargo.lock")
    entry = {"source": {"path": path.as_posix()}, "packages": [
        {"package": {"name": "ring", "version": "0.17.14", "ecosystem": "crates.io"}}]}
    report = {"results": [entry]}
    packages = scanner_inventory(gate.validate_inventory, report, [path], True)
    assert packages[0]["_admission_source"] == str(path)
    assert report["results"][0]["source"]["path"] == path.as_posix()
    for rejected in (
        {"results": []},
        {"results": [entry, entry]},
        {"results": [{**entry, "source": {"path": "D:/a/repo/other/Cargo.lock"}}]},
        {"results": [{**entry, "source": {"path": "fixtures/jwt-hmac-consumer/Cargo.lock"}}]},
    ):
        try:
            scanner_inventory(gate.validate_inventory, rejected, [path], True)
        except ValueError:
            continue
        raise ValueError("Inventory regression accepted missing/duplicate/unrequested source")
    return {"windowsSlashAlias": True, "rawReportUnchanged": True, "negativeCases": 4}


def inspect_graph():
    consumer_lock()
    for path in ordinary_locks_for_proof():
        owned_path(path)
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
    path = consumer_lock()
    spec = importlib.util.spec_from_file_location("hmac_osv_gate", ROOT / "scripts/osv-dependency-gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    ordinary_locks = [owned_path(item) for item in gate.lockfiles()]
    gate.lockfiles = lambda: sorted({*ordinary_locks, path})
    validator = gate.validate_inventory
    gate.validate_inventory = lambda report, paths: scanner_inventory(validator, report, paths, os.name == "nt")
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
    expected = {path.relative_to(ROOT).as_posix(): hashlib.sha256(owned_path(path).read_bytes()).hexdigest()
                for path in [*ordinary_locks_for_proof(), consumer_lock()]}
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
               "--no-default-features", "--features", "jwt-hmac", "--output-format", "regular"]
    def run(label):
        log = output.with_name(output.stem + "." + label + ".log")
        with log.open("w") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=900, shell=False)
        text = log.read_text()
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)
        if not valid_kani_output(text, label, result.returncode):
            # Bound diagnostics; these pure-policy logs contain only source,
            # symbolic kinds/lengths and verifier output, never production keys.
            print("Kani " + label + " exit=" + str(result.returncode) + " log tail:\n" + text[-32768:], file=sys.stderr)
            raise ValueError("Kani " + label + " did not positively classify both expected harnesses; inspect saved log")
    try:
        source.write_text(mutant)
        run("red")
    finally:
        source.write_text(original)
    run("green")
    if source.read_text() != original:
        raise ValueError("Kani mutation did not restore source")
    return {"version": "0.68.0", "mutantFailures": 2, "provedHarnesses": 2,
            "kinds": 3, "lengthDomain": "all usize values on x86_64", "noHeapOrLoopBound": True,
            "stubs": [], "nonVacuityCovers": KEY_COVERS + MESSAGE_COVERS, "automaticAssertionReachability": True,
            "concurrencyOrCryptographyProved": False, "sourceRestored": True}


def ordinary_locks_for_proof():
    spec = importlib.util.spec_from_file_location("proof_osv_gate", ROOT / "scripts/osv-dependency-gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate.lockfiles()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--admit", action="store_true", help="Run unchanged pinned OSV core over root/tool/consumer locks before builds")
    parser.add_argument("--self-test", action="store_true", help="Exercise scanner path identity and fail-closed inventory checks without builds")
    parser.add_argument("--prove-kani", action="store_true", help="Run exact red/green bounded kernels using the approved installed CI tool")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"status": "failed"}, indent=2) + "\n")
    if args.self_test:
        if args.admit or args.prove_kani:
            raise ValueError("Inventory regressions are separate from admission/proof")
        args.output.write_text(json.dumps({"status": "pass", **inventory_self_test(), **proof_parser_self_test(), **ownership_self_test()}, indent=2) + "\n")
        return 0
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

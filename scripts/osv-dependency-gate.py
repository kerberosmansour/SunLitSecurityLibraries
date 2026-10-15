#!/usr/bin/env python3
"""Scan resolved direct/transitive dependencies before installation or execution.

Bootstrap only the official, SHA-256-pinned OSV binary. No package installation,
build, lockfile mutation, remediation, or lifecycle script execution occurs here.
"""
import argparse
from datetime import date
import hashlib
import json
import tomllib
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request

VERSION = "v2.7.0"
# Official release asset digests, independently matched to SHA256SUMS.
ASSETS = {
    ("Darwin", "arm64"): ("osv-scanner_darwin_arm64", "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b"),
    ("Darwin", "x86_64"): ("osv-scanner_darwin_amd64", "e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45"),
    ("Linux", "x86_64"): ("osv-scanner_linux_amd64", "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"),
    ("Linux", "arm64"): ("osv-scanner_linux_arm64", "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7"),
    ("Windows", "x86_64"): ("osv-scanner_windows_amd64.exe", "9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438"),
    ("Windows", "arm64"): ("osv-scanner_windows_arm64.exe", "3e630381c1f1fd3c9c4d447e6ff2ef6c737083371722773db8337eead0f97962"),
}
ROOT = Path(__file__).resolve().parents[1]
MAX_BINARY = 64 * 1024 * 1024
LOCK_NAMES = {"Cargo.lock", "pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb", "poetry.lock", "Pipfile.lock", "uv.lock", "go.sum", "composer.lock", "Gemfile.lock", "packages.lock.json", "requirements.txt"}
FIXTURE_PARTS = {"fixtures", "testdata", "__fixtures__"}
TOOLCHAIN_EXCEPTION_SCHEMA = "sunlit.toolchain-osv-exceptions/v1"
TOOLCHAIN_EXCEPTION_KEYS = {
    "lockfile", "ecosystem", "package", "version", "advisory",
    "owner", "expires", "kind", "reason",
}
MAX_TOOLCHAIN_EXCEPTION_DAYS = 31

class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise ValueError("Scanner download attempted a non-HTTPS redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def verify(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BINARY:
        raise ValueError("Scanner path is invalid")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError("Scanner checksum mismatch; refusing execution")


def scanner():
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x86_64" if machine in {"amd64", "x86_64"} else machine
    asset, digest = ASSETS[(platform.system(), arch)]
    cache = ROOT / ".cache" / "osv-dependency-gate" / VERSION
    cache.mkdir(parents=True, exist_ok=True)
    if any(parent.is_symlink() for parent in (cache, cache.parent, cache.parent.parent)):
        raise ValueError("Scanner cache directories must not be symlinks")
    binary = cache / asset
    if not binary.exists():
        request = urllib.request.Request(f"https://github.com/google/osv-scanner/releases/download/{VERSION}/{asset}", headers={"User-Agent": "Sunlit-OSV-dependency-gate"})
        opener = urllib.request.build_opener(HttpsRedirect())
        with opener.open(request, timeout=60) as response:
            data = response.read(MAX_BINARY + 1)
        if len(data) > MAX_BINARY or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Scanner download failed size/checksum verification")
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as staged:
            staged.write(data)
            temporary = Path(staged.name)
        try:
            temporary.chmod(0o755)
            temporary.replace(binary)
        finally:
            temporary.unlink(missing_ok=True)
    verify(binary, digest)
    return binary


def lockfiles():
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode("utf-8").split("\0")
    # Include unstaged root locks while an agent is preparing a dependency update.
    candidates = {ROOT / name for name in tracked if name and Path(name).name in LOCK_NAMES and not FIXTURE_PARTS.intersection(Path(name).parts)}
    candidates.update(ROOT / name for name in LOCK_NAMES if (ROOT / name).exists())
    paths = sorted(candidates)
    if not paths:
        raise ValueError("No production dependency lockfiles discovered; refusing an empty scan")
    for path in paths:
        if path.is_symlink() or not path.is_file() or ROOT not in path.resolve().parents:
            raise ValueError("Dependency lockfile must be a real file inside the repository")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".cache" / "osv-dependency-gate" / "findings.json")
    args = parser.parse_args()
    paths = lockfiles()
    configs = []
    for directory, subdirs, files in os.walk(ROOT, followlinks=False):
        subdirs[:] = [part for part in subdirs if part not in {".git", "node_modules", "target", ".cache"}]
        if "osv-scanner.toml" in files:
            configs.append(Path(directory) / "osv-scanner.toml")
    for config in configs:
        if config.is_symlink():
            raise ValueError("OSV configuration must not be a symlink")
        settings = tomllib.loads(config.read_text(encoding="utf-8"))
        if settings.get("IgnoredPackages") or settings.get("PackageOverrides"):
            raise ValueError("Package-wide OSV ignores are forbidden")
        ignores = settings.get("IgnoredVulns", [])
        if any(not item.get("ignoreUntil") or not item.get("reason") for item in ignores):
            raise ValueError("OSV vulnerability exceptions require reason and expiry")
        if any(str(item.get("id", "")).startswith("MAL-") for item in ignores):
            raise ValueError("Known malicious packages cannot be ignored")
    lock_digests = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    binary = scanner()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Explicit empty config overrides every per-directory config. Evaluate
    # every advisory ourselves, after seeing every advisory alias.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", dir=args.output.parent, delete=False) as config:
        config.write("# Admission deliberately scans without scanner suppressions.\n")
        config_path = Path(config.name)
    command = [str(binary), "scan", "source", "--format=json", "--all-packages", "--all-vulns", "--no-call-analysis=rust", "--no-call-analysis=go", "--config=" + str(config_path)] + ["--lockfile=" + str(path) for path in paths]
    try:
        with args.output.open("wb") as report, args.output.with_suffix(".stderr.txt").open("wb") as diagnostics:
            # Executable bytes were checksum-verified; tracked paths are separate
            # --lockfile= argv values; no shell or Rust/Go call analysis is enabled.
            result = subprocess.run(command, cwd=ROOT, stdout=report, stderr=diagnostics, timeout=600, shell=False)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
    finally:
        config_path.unlink(missing_ok=True)
    report = json.loads(args.output.read_text(encoding="utf-8"))
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != digest for path, digest in lock_digests.items()):
        raise ValueError("Dependency lock changed during scanning")
    packages = validate_inventory(report, paths)
    package_count = len(packages)
    for path in paths:
        expected = expected_inventory(path)
        actual = {(re.sub(r"[-_.]+", "-", item["package"]["name"]).lower() if item["package"]["ecosystem"] == "PyPI" else item["package"]["name"], item["package"]["version"]) for item in packages if item["_admission_source"] == str(path)}
        if actual != expected:
            raise ValueError("Scanner inventory does not match every resolved lockfile package")
    # Scan every advisory. Ordinary vulnerabilities are reported, not suppressed;
    # known malware and incomplete/error results still block dependency execution.
    summary = findings_summary(packages)
    args.output.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    reviewed_toolchain = reviewed_toolchain_exceptions(packages)
    code = scan_exit_status(result.returncode, packages, [])
    if code == 0 and (ROOT / "Cargo.lock").is_file():
        guard = ROOT / "scripts/check-native-dependencies.py"
        if not guard.is_file() or guard.is_symlink():
            raise ValueError("Rust admission requires the native dependency guard")
        subprocess.run([sys.executable, str(guard)], cwd=ROOT, check=True, timeout=120)

    receipt = {
        "scannerVersion": VERSION,
        "reportSHA256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "lockfiles": [{"path": path.relative_to(ROOT).as_posix(), "sourcePath": str(path), "sha256": lock_digests[path]} for path in paths],
        "admissionExitCode": code,
        "admissionPolicy": "malware-block-vulnerabilities-report-v1",
        "maliciousFindings": summary["maliciousFindings"],
        "vulnerabilityFindings": summary["vulnerabilityFindings"],
        "reviewedToolchainExceptions": reviewed_toolchain,
    }
    args.output.with_suffix(".receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    if summary["vulnerabilityFindings"]:
        count = summary["vulnerabilityFindings"]
        print(f"WARNING: {count} dependency vulnerability findings require review and remediation; they do not block OSV admission. See the full report and summary.")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::warning title=Dependency vulnerabilities::{count} vulnerability findings require remediation. Full details are retained in the OSV report and summary artifact.")
    print(f"OSV {VERSION}: scanned {len(paths)} resolved lockfiles and {package_count} packages; exit {code}; report: {args.output}")
    return code


def findings_summary(packages):
    findings = []
    for item in packages:
        for vuln in item.get("vulnerabilities", []):
            if (not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str)
                    or not vuln["id"].strip() or not isinstance(vuln.get("aliases", []), list)
                    or not all(isinstance(alias, str) and alias.strip() for alias in vuln.get("aliases", []))):
                raise ValueError("Malformed advisory identity/aliases")
            ids = {vuln["id"], *vuln.get("aliases", [])}
            if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", identity) for identity in ids):
                raise ValueError("Malformed advisory identity/aliases")
            malicious = any(identity.upper().startswith("MAL-") for identity in ids)
            findings.append({"kind": "malware" if malicious else "vulnerability",
                             "source": item.get("_admission_source"),
                             "package": dict(item["package"]), "id": vuln["id"],
                             "aliases": vuln.get("aliases", [])})
    return {"policy": "malware-block-vulnerabilities-report-v1",
            "maliciousFindings": sum(item["kind"] == "malware" for item in findings),
            "vulnerabilityFindings": sum(item["kind"] == "vulnerability" for item in findings),
            "findings": findings}


def scan_exit_status(returncode, packages, exceptions):
    # Keep the legacy argument for callers; exceptions never affect malware.
    summary = findings_summary(packages)
    if returncode == 1 and not summary["findings"]:
        raise ValueError("Scanner findings exit lacks represented advisories")
    return returncode if returncode not in (0, 1) else (1 if summary["maliciousFindings"] else 0)


def validate_inventory(report, paths):
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError("Scanner did not return a valid dependency inventory")
    inventory = {}
    requested = {str(path): path for path in paths}
    packages = []
    for entry in report["results"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("source"), dict) or not isinstance(entry.get("packages"), list):
            raise ValueError("Malformed scanner source/package inventory")
        path = entry["source"].get("path")
        if not isinstance(path, str) or not entry["packages"] or path in inventory:
            raise ValueError("Empty, duplicate or malformed lockfile inventory")
        if path not in requested:
            raise ValueError("Scanner returned an unrequested source")
        expected_ecosystem = "crates.io" if requested[path].name == "Cargo.lock" else "PyPI" if requested[path].name == "requirements.txt" else "npm" if requested[path].name in {"pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json"} else None
        for item in entry["packages"]:
            if not isinstance(item, dict) or not isinstance(item.get("package"), dict):
                raise ValueError("Malformed resolved package")
            if not all(isinstance(item["package"].get(key), str) and item["package"][key] for key in ("name", "version", "ecosystem")):
                raise ValueError("Resolved package is missing identity")
            if expected_ecosystem is None or item["package"]["ecosystem"] != expected_ecosystem:
                raise ValueError("Scanner ecosystem differs from requested lockfile")
            if not isinstance(item.get("vulnerabilities", []), list):
                raise ValueError("Malformed advisory list")
        inventory[path] = entry["packages"]
        for item in entry["packages"]:
            copy = dict(item)
            copy["_admission_source"] = path
            packages.append(copy)
    if not all(str(path) in inventory for path in paths):
        raise ValueError("Scanner omitted a requested lockfile; refusing partial scan")
    return packages


def expected_inventory(path):
    if path.name == "Cargo.lock":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return {(item["name"], item["version"]) for item in data["package"]}
    if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data.get("packages"), dict):
            raise ValueError("npm admission requires the resolved packages lock schema")
        return {(item.get("name") or name.split("node_modules/")[-1], item["version"]) for name, item in data["packages"].items() if name and item.get("version") and not item.get("link")}
    if path.name == "requirements.txt":
        pairs = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9._-]+)==([^\s;]+) --hash=sha256:[0-9a-f]{64}", line)
            if not match:
                raise ValueError("Python tool admission requires exact hash-pinned wheels")
            pairs.add((re.sub(r"[-_.]+", "-", match[1]).lower(), match[2]))
        return pairs
    if path.name == "pnpm-lock.yaml":
        # Independently count identity keys in pnpm's packages mapping. This
        # intentionally refuses unsupported lock shapes rather than claiming a
        # partial inventory. It does not interpret or execute general YAML.
        active = False
        pairs = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if line == "packages:":
                active = True
                continue
            if active and line and not line.startswith(" "):
                break
            if active and line.startswith("  ") and not line.startswith("   ") and line.endswith(":"):
                identity = line.strip()[:-1]
                if identity.startswith("'") and identity.endswith("'"):
                    identity = identity[1:-1].replace("''", "'")
                elif identity.startswith('"'):
                    identity = json.loads(identity)
                package, version = identity.rsplit("@", 1)
                pairs.add((package, version))
        if not pairs:
            raise ValueError("pnpm dependency identity mapping is empty/unsupported")
        return pairs
    raise ValueError("Lockfile format needs an explicit complete-inventory admission check")


def reviewed_exceptions(packages):
    path = ROOT / "supply-chain/maintenance-exceptions.json"
    if not path.exists():
        return []
    if path.is_symlink():
        raise ValueError("Exception manifest must not be a symlink")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("exceptions"), list):
        raise ValueError("Invalid reviewed exception manifest")
    identities = {(item["package"]["name"], item["package"]["version"]) for item in packages}
    for entry in manifest["exceptions"]:
        if not isinstance(entry, dict) or not all(isinstance(entry.get(key), str) and entry[key] for key in ("package", "version", "owner", "expires", "reason", "kind")):
            raise ValueError("Exception lacks exact identity/owner/expiry/reachability reason")
        if date.fromisoformat(entry["expires"]) <= date.today():
            raise ValueError("Dependency exception expired")
        if (entry["package"], entry["version"]) not in identities:
            raise ValueError("Excepted dependency changed version or is absent; re-review the disposition")
        if str(entry.get("advisory", "")).startswith("MAL-"):
            raise ValueError("Known malicious packages cannot be excepted")
    return manifest["exceptions"]


def reviewed_toolchain_exceptions(packages):
    """Require exact, expiring review records for vulnerable CI toolchains.

    The raw OSV report and summary remain unchanged. These records document a
    bounded disposition; they never suppress an advisory or change malware
    blocking.
    """
    findings_summary(packages)  # Validate every advisory identity and alias.
    root = ROOT.resolve()
    toolchain_root = ROOT / "tools/security-toolchains"
    toolchain_packages = []
    findings = []
    for item in packages:
        source = item.get("_admission_source")
        if not isinstance(source, str):
            continue
        source_path = Path(source)
        try:
            relative = source_path.resolve().relative_to(root).as_posix()
        except ValueError:
            raise ValueError("Scanner toolchain source is outside the repository")
        if not relative.startswith("tools/security-toolchains/"):
            continue
        package = item["package"]
        package_identity = {
            "lockfile": relative,
            "ecosystem": package["ecosystem"],
            "package": package["name"],
            "version": package["version"],
        }
        toolchain_packages.append(package_identity)
        for vuln in item.get("vulnerabilities", []):
            identities = frozenset({vuln["id"], *vuln.get("aliases", [])})
            if any(identity.upper().startswith("MAL-") for identity in identities):
                raise ValueError("Known malicious packages cannot be excepted")
            findings.append({**package_identity, "identities": identities})

    manifests = [] if not toolchain_root.exists() else sorted(toolchain_root.glob("*/exceptions.json"))
    records = []
    for manifest_path in manifests:
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("Toolchain exception manifest must be a real file, not a symlink")
        parent = manifest_path.parent
        while parent != root:
            if parent.is_symlink():
                raise ValueError("Toolchain exception manifest parent must not be a symlink")
            parent = parent.parent
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict) or set(manifest) != {"schema", "exceptions"}
                or manifest.get("schema") != TOOLCHAIN_EXCEPTION_SCHEMA
                or not isinstance(manifest.get("exceptions"), list)):
            raise ValueError("Invalid toolchain exception manifest schema")
        manifest_dir = manifest_path.parent.resolve().relative_to(root).as_posix()
        for entry in manifest["exceptions"]:
            if (not isinstance(entry, dict) or set(entry) != TOOLCHAIN_EXCEPTION_KEYS
                    or not all(isinstance(entry.get(key), str) and entry[key].strip()
                               for key in TOOLCHAIN_EXCEPTION_KEYS)):
                raise ValueError("Invalid toolchain exception entry schema")
            if entry["kind"] != "unreachable-code-path":
                raise ValueError("Toolchain exception kind must be unreachable-code-path")
            try:
                expires = date.fromisoformat(entry["expires"])
            except ValueError as error:
                raise ValueError("Toolchain exception expiry must be a canonical ISO date") from error
            if expires.isoformat() != entry["expires"]:
                raise ValueError("Toolchain exception expiry must be a canonical ISO date")
            if expires <= date.today():
                raise ValueError("Toolchain exception expired")
            if (expires - date.today()).days > MAX_TOOLCHAIN_EXCEPTION_DAYS:
                raise ValueError("Toolchain exception expiry exceeds the maximum review window")
            if len(entry["owner"].strip()) < 3 or len(entry["reason"].strip()) < 40:
                raise ValueError("Toolchain exception requires a named owner and specific reachability reason")
            relative = Path(entry["lockfile"])
            if (relative.is_absolute() or ".." in relative.parts
                    or relative.as_posix() != entry["lockfile"]
                    or relative.parent.as_posix() != manifest_dir):
                raise ValueError("Toolchain exception lockfile must be exact and local to its manifest")
            lock = ROOT / relative
            if lock.is_symlink() or not lock.is_file() or lock.resolve().parent != manifest_path.parent.resolve():
                raise ValueError("Toolchain exception lockfile must be a real file")
            if entry["advisory"].upper().startswith("MAL-"):
                raise ValueError("Known malicious packages cannot be excepted")
            identity_matches = [package for package in toolchain_packages if all(
                package[key] == entry[key]
                for key in ("lockfile", "ecosystem", "package", "version")
            )]
            if not identity_matches:
                raise ValueError("Toolchain exception dependency identity changed or is absent")
            advisory_matches = [finding for finding in findings if all(
                finding[key] == entry[key]
                for key in ("lockfile", "ecosystem", "package", "version")
            ) and entry["advisory"] in finding["identities"]]
            if not advisory_matches:
                related_findings = [finding for finding in findings if all(
                    finding[key] == entry[key]
                    for key in ("lockfile", "ecosystem", "package", "version")
                )]
                if not related_findings:
                    raise ValueError("Toolchain exception is stale because the advisory disappeared")
                raise ValueError("Toolchain exception advisory does not match the scanner finding")
            if len(advisory_matches) != 1:
                raise ValueError("Toolchain exception advisory match is ambiguous")
            records.append(dict(entry))

    covered = set()
    for index, finding in enumerate(findings):
        matching = [entry for entry in records if all(
            entry[key] == finding[key]
            for key in ("lockfile", "ecosystem", "package", "version")
        ) and entry["advisory"] in finding["identities"]]
        if len(matching) != 1:
            raise ValueError("Every toolchain vulnerability requires an exact reviewed exception")
        covered.add(index)
    if len(covered) != len(findings):
        raise ValueError("Every toolchain vulnerability requires an exact reviewed exception")
    return records


def unaccepted_findings(packages, exceptions):
    found = False
    for item in packages:
        package = item["package"]
        for vuln in item.get("vulnerabilities", []):
            if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not isinstance(vuln.get("aliases", []), list) or not all(isinstance(alias, str) for alias in vuln.get("aliases", [])):
                raise ValueError("Malformed advisory identity/aliases")
            ids = {vuln["id"], *vuln.get("aliases", [])}
            if any(advisory.startswith("MAL-") for advisory in ids):
                found = True
                continue
            accepted = any(package["ecosystem"] == "crates.io" and item.get("_admission_source") == str(ROOT / "Cargo.lock") and entry.get("advisory") in ids and entry["package"] == package["name"] and entry["version"] == package["version"] for entry in exceptions)
            if not accepted:
                found = True
    return found


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"OSV dependency gate failed: {error}", file=sys.stderr)
        sys.exit(2)

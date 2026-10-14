#!/usr/bin/env python3
"""Admit an exact script-disabled Cargo package before verification/publication.

Require clean source, original manifest equality and a checksum-identical subset
of the admitted product graph. Published sibling checksums must be recorded from
already verified registry bytes. Tool graphs never inherit library exceptions.
"""
import argparse
import hashlib
import gzip
import io
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("osv_gate", ROOT / "scripts/osv-dependency-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)



def normalized_dependencies(manifest, workspace, *, normalized=False):
    def table(dependencies, section):
        result = {}
        for name, value in dependencies.items():
            value = {"version": value} if isinstance(value, str) else dict(value)
            if value.pop("workspace", False):
                inherited = workspace["workspace"]["dependencies"][name]
                inherited = {"version": inherited} if isinstance(inherited, str) else dict(inherited)
                features = inherited.get("features", []) + value.get("features", [])
                inherited.update(value)
                if features:
                    inherited["features"] = features
                value = inherited
            if normalized and "path" in value:
                raise ValueError("Published manifest must not retain dependency paths")
            if section == "dev-dependencies" and "path" in value and "version" not in value:
                continue  # Cargo omits path-only development dependencies.
            value.pop("path", None)
            if "features" in value:
                value["features"] = sorted(set(value["features"]))
            result[name] = value
        return result
    sections = ("dependencies", "dev-dependencies", "build-dependencies")
    result = {section: table(manifest.get(section, {}), section) for section in sections}
    result["target"] = {target: {section: table(config.get(section, {}), section) for section in sections} for target, config in manifest.get("target", {}).items()}
    return result



def source_targets(root, name):
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--locked", "--offline", "--format-version", "1"], cwd=root))
    package = next(p for p in metadata["packages"] if p["name"] == name and Path(p["manifest_path"]) == root / "crates" / name / "Cargo.toml")
    result = {section: [] for section in ("lib", "bin", "test", "example", "bench")}
    source_manifest = tomllib.loads((root / "crates" / name / "Cargo.toml").read_text())
    for target in package["targets"]:
        if len(target["kind"]) != 1 or target["kind"][0] not in result:
            raise ValueError("Source target kind requires explicit release review")
        section = target["kind"][0]
        resolved = {"name": target["name"], "path": Path(target["src_path"]).relative_to(root / "crates" / name).as_posix()}
        declared = source_manifest.get(section, [])
        declared = [declared] if isinstance(declared, dict) else declared
        matches = [entry for entry in declared if section == "lib" or entry.get("name") == resolved["name"] or ("name" not in entry and entry.get("path") == resolved["path"])]
        if len(matches) > 1:
            raise ValueError("Ambiguous source target authority")
        if matches:
            resolved.update({key: value for key, value in matches[0].items() if key not in {"name", "path"}})
        result[section].append(resolved)
    return {k: sorted(v, key=lambda t: (t["name"], t["path"])) for k, v in result.items()}


def normalized_lints(lints):
    """Cargo makes the documented zero priority explicit when packaging."""
    result = {}
    for group, entries in lints.items():
        if not isinstance(entries, dict):
            raise ValueError("Inherited lint authority requires explicit review")
        result[group] = {}
        for name, value in entries.items():
            value = {"level": value} if isinstance(value, str) else dict(value)
            value.setdefault("priority", 0)
            result[group][name] = value
    return result


def candidate(archive, root, commit, published):
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Release archive is invalid or exceeds bound")
    with archive.open("rb") as file:
        archive_data = file.read(16 * 1024 * 1024 + 1)
    if len(archive_data) > 16 * 1024 * 1024:
        raise ValueError("Release archive exceeds bound")
    archive_digest = hashlib.sha256(archive_data).hexdigest()
    with gzip.GzipFile(fileobj=io.BytesIO(archive_data)) as compressed:
        expanded = compressed.read(64 * 1024 * 1024 + 1)
    if len(expanded) > 64 * 1024 * 1024:
        raise ValueError("Release archive decompressed data exceeds bound")
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as tar:
        members = []
        expanded_size = 0
        for member in tar:
            expanded_size += member.size
            if len(members) >= 10000 or expanded_size > 64 * 1024 * 1024:
                raise ValueError("Release archive inventory exceeds bound")
            members.append(member)
        names = [m.name for m in members]
        if len(names) != len(set(names)) or any(m.name.startswith("/") or ".." in m.name.split("/") or "\\" in m.name or not (m.isfile() or m.isdir()) for m in members):
            raise ValueError("Release archive has unsafe or duplicate members")
        prefix = archive.name.removesuffix(".crate") + "/"
        if any(not n.startswith(prefix) for n in names):
            raise ValueError("Release archive identity prefix mismatch")
        def read(name):
            member = tar.getmember(prefix + name)
            if not member.isfile() or member.size > 8 * 1024 * 1024:
                raise ValueError("Release metadata is invalid or exceeds bound")
            return tar.extractfile(member).read()
        # Bind every shipped source byte to the clean Git commit, not just the
        # archive's self-reported VCS record. Only Cargo's three metadata files
        # are generated; Cargo.toml.orig is bound to the source manifest below.
        original = read("Cargo.toml.orig")
        manifest = tomllib.loads(original.decode("utf-8"))
        package = manifest["package"]
        name, version = package["name"], package["version"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"\d+\.\d+\.\d+", version) or prefix != f"{name}-{version}/":
            raise ValueError("Release package identity invalid")
        source = root / "crates" / name / "Cargo.toml"
        if source.is_symlink() or source.read_bytes() != original or package.get("publish") is False:
            raise ValueError("Release source manifest differs from clean repository")
        vcs = json.loads(read(".cargo_vcs_info.json"))
        if vcs["git"]["sha1"] != commit or vcs["git"].get("dirty", False) or vcs["path_in_vcs"] != f"crates/{name}":
            raise ValueError("Release package does not match clean source commit")
        for member in members:
            relative = member.name[len(prefix):]
            if not member.isfile() or relative in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}:
                continue
            source_path = f"crates/{name}/{relative}"
            expected_bytes = subprocess.check_output(["git", "show", f"{commit}:{source_path}"], cwd=root)
            if tar.extractfile(member).read() != expected_bytes:
                raise ValueError("Packaged source differs from the clean Git commit")
        normalized = tomllib.loads(read("Cargo.toml").decode("utf-8"))
        allowed_tables={"package","lib","bin","test","example","bench","dependencies","dev-dependencies","build-dependencies","target","features","lints"}
        if set(normalized) - allowed_tables:
            raise ValueError("Unexpected top-level normalized manifest authority")
        workspace = tomllib.loads((root / "Cargo.toml").read_text())
        if normalized_dependencies(normalized, workspace, normalized=True) != normalized_dependencies(manifest, workspace) or normalized.get("features", {}) != manifest.get("features", {}):
            raise ValueError("Normalized dependency/feature authority differs from clean source")
        for key, value in manifest["package"].items():
            if normalized["package"].get(key) != value:
                raise ValueError("Normalized package settings differ from clean source")
        generated = set(normalized["package"]) - set(manifest["package"])
        if generated - {"build", "autolib", "autobins", "autoexamples", "autotests", "autobenches"} or any(normalized["package"][key] is not False for key in generated):
            raise ValueError("Unexpected normalized package authority")
        if normalized_lints(normalized.get("lints", {})) != normalized_lints(manifest.get("lints", {})):
            raise ValueError("Normalized lint authority differs from clean source")
        if (normalized["package"]["name"], normalized["package"]["version"]) != (name, version):
            raise ValueError("Normalized package identity differs")
        if normalized["package"].get("build", False) != manifest["package"].get("build", False) or normalized["package"].get("links") != manifest["package"].get("links"):
            raise ValueError("Normalized build authority differs")
        targets_from_source = source_targets(root, name)
        actual_targets = {}
        for section in ("lib", "bin", "test", "example", "bench"):
            targets = normalized.get(section, [])
            targets = [targets] if isinstance(targets, dict) else targets
            actual_targets[section] = []
            for target in targets:
                path = target.get("path")
                if not path or path.startswith("/") or ".." in path.split("/") or prefix + path not in names:
                    raise ValueError("Normalized target points outside verified package sources")
                actual = dict(target)
                actual.setdefault("name", name.replace("-", "_") if section == "lib" else None)
                actual_targets[section].append(actual)
        if {k: sorted(v, key=lambda t: (t["name"], t["path"])) for k, v in actual_targets.items()} != targets_from_source:
            raise ValueError("Normalized targets differ from clean source authority")
        lock_bytes = read("Cargo.lock")
        packages = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
    root_packages = {(p["name"], p["version"]): p for p in tomllib.loads((root / "Cargo.lock").read_text())["package"]}
    identities = [(p["name"], p["version"]) for p in packages]
    if len(identities) != len(set(identities)) or identities.count((name, version)) != 1:
        raise ValueError("Release package has ambiguous identities")
    for p in packages:
        identity = (p["name"], p["version"])
        expected = root_packages.get(identity)
        if expected is None:
            raise ValueError("Release package adds a dependency outside the admitted root graph")
        if identity == (name, version):
            if p.get("source") or p.get("checksum"):
                raise ValueError("Release root must be the local package")
        elif expected.get("source"):
            if (p.get("source"), p.get("checksum")) != (expected.get("source"), expected.get("checksum")):
                raise ValueError("Release dependency provenance/integrity differs from admitted root")
        else:
            record = published.get(p["name"])
            if not record or (record.get("version"), record.get("sourceCommit"), record.get("checksum")) != (p["version"], commit, p.get("checksum")) or p.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                raise ValueError("Release sibling must match independently verified published bytes")
    return name, version, lock_bytes, archive_digest



def verify_unchanged_archive(path, expected):
    with path.open("rb") as source:
        current = source.read(16 * 1024 * 1024 + 1)
    if path.is_symlink() or hashlib.sha256(current).hexdigest() != expected:
        raise ValueError("Release archive changed during admission")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--root-report", type=Path, required=True)
    parser.add_argument("--root-receipt", type=Path, required=True)
    parser.add_argument("--published-records", type=Path, required=True)
    args = parser.parse_args()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("Release checkout must be clean")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    receipt = json.loads(args.root_receipt.read_text())
    if receipt["admissionExitCode"] != 0 or receipt["scannerVersion"] != gate.VERSION or receipt["reportSHA256"] != hashlib.sha256(args.root_report.read_bytes()).hexdigest():
        raise ValueError("Root admission evidence invalid")
    paths = gate.lockfiles()
    bindings = {r["path"]: r["sha256"] for r in receipt["lockfiles"]}
    if bindings != {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}:
        raise ValueError("Root graph changed since admission")
    root_packages = gate.validate_inventory(json.loads(args.root_report.read_text()), paths)
    for path in paths:
        actual = {(re.sub(r"[-_.]+", "-", p["package"]["name"]).lower() if p["package"]["ecosystem"] == "PyPI" else p["package"]["name"], p["package"]["version"]) for p in root_packages if p["_admission_source"] == str(path)}
        if actual != gate.expected_inventory(path):
            raise ValueError("Root scan omitted resolved dependency identities")
    exceptions = gate.reviewed_exceptions(root_packages)
    if gate.unaccepted_findings(root_packages, exceptions):
        raise ValueError("Root report contains unaccepted findings")
    records = json.loads(args.published_records.read_text())
    if not isinstance(records, list) or len({r['name'] for r in records}) != len(records):
        raise ValueError("Invalid published prerequisite records")
    name, version, lock_bytes, archive_digest = candidate(args.archive, ROOT, commit, {r['name']: r for r in records})
    folder = ROOT / ".cache/release-admission" / f"{name}-{version}"
    folder.mkdir(parents=True, exist_ok=True)
    if any(p.is_symlink() for p in (folder, folder.parent, folder.parent.parent)):
        raise ValueError("Release admission cache must not contain symlinks")
    lock = folder / "Cargo.lock"
    if lock.is_symlink():
        raise ValueError("Candidate lock cannot be a symlink")
    lock.write_bytes(lock_bytes)
    report = folder / "osv.json"
    if any(p.is_symlink() for p in (report, folder / "osv.stderr.txt", folder / "receipt.json", folder / "empty.toml")):
        raise ValueError("Release admission artifacts cannot be symlinks")
    with (folder / "empty.toml").open("w") as config:
        config.write("# No scanner suppression.\n")
    command = [str(gate.scanner()), "scan", "source", "--all-packages", "--all-vulns", "--no-call-analysis=rust", "--no-call-analysis=go", "--format=json", "--config=" + str(folder / "empty.toml"), "--lockfile=" + str(lock)]
    with report.open("wb") as output, (folder / "osv.stderr.txt").open("wb") as diagnostics:
        # Checksum-verified executable; bounded validated repository lock paths
        # are separate --lockfile= arguments, never shell text or option inputs.
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=diagnostics, shell=False, timeout=600)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
    if result.returncode not in (0, 1):
        raise ValueError("Candidate scanner failed")
    packages = gate.validate_inventory(json.loads(report.read_text()), [lock])
    if {(p["package"]["name"], p["package"]["version"]) for p in packages} != gate.expected_inventory(lock) or lock.read_bytes() != lock_bytes:
        raise ValueError("Candidate scan inventory changed or incomplete")
    # Only after source and exact checksum-subset review can the same legitimate
    # product exception apply. Tool graphs cannot use this archive-bound path.
    reviewed = [dict(p, _admission_source=str(ROOT / "Cargo.lock")) for p in packages]
    if gate.scan_exit_status(result.returncode, reviewed, exceptions) != 0:
        raise ValueError("Candidate has unaccepted vulnerability/malware findings")
    subprocess.run([sys.executable, str(ROOT / "scripts/check-native-dependencies.py")], cwd=ROOT, check=True, timeout=120)
    verify_unchanged_archive(args.archive, archive_digest)
    (folder / "receipt.json").write_text(json.dumps({"sourceCommit": commit, "name": name, "version": version, "packageSHA256": archive_digest, "lockSHA256": hashlib.sha256(lock_bytes).hexdigest(), "reportSHA256": hashlib.sha256(report.read_bytes()).hexdigest(), "scannerVersion": gate.VERSION, "admissionExitCode": 0}, indent=2) + "\n")
    print(f"Admitted {name} {version}: exact source and {len(packages)} packaged dependencies; {report}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"Release dependency admission failed: {error}", file=sys.stderr)
        sys.exit(2)

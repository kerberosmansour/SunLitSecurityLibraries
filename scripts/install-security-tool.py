#!/usr/bin/env python3
"""Build a provenance-pinned security tool using its OSV-admitted frozen lock.

Registry source is verified before extraction; no resolver or installer may
select a dependency outside the reviewed tool lock. Cargo-vet uses a documented
manifest-only transport/progress overlay, leaving audit evaluation code unchanged.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RECIPES = ROOT / "tools/security-toolchains/recipes.json"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_SOURCE = 64 * 1024 * 1024


def extract_source(data, directory, prefix):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 10000 or sum(member.size for member in members) > MAX_SOURCE:
            raise ValueError("Tool archive exceeds source bounds")
        for member in members:
            if not member.name.startswith(prefix) or member.issym() or member.islnk():
                raise ValueError("Tool archive has invalid prefix/link")
            relative = Path(member.name[len(prefix):])
            if relative.anchor or ".." in relative.parts or "\\" in member.name or any(":" in part for part in relative.parts) or directory.resolve() not in (directory / relative).resolve().parents or member.size > MAX_ARCHIVE:
                raise ValueError("Tool archive path/size is invalid")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("Tool archive contains a special file")
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(member).read())


def apply_manifest_edits(source, edits):
    manifest = source / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    for package, edit in edits.items():
        pattern = r'(?m)(^\[dependencies\.' + re.escape(package) + r'\]\nversion = )' + re.escape(json.dumps(edit["from"]))
        text, count = re.subn(pattern, lambda match: match[1] + json.dumps(edit["to"]), text)
        if count != 1:
            raise ValueError("Documented tool manifest overlay did not match exactly once")
    # Registry packages are standalone; prevent accidental membership in the
    # product workspace while building the verified source beneath its cache.
    if "workspace" not in tomllib.loads(text):
        text += "\n[workspace]\n"
    manifest.write_text(text, encoding="utf-8")


def verify_admission(tool, recipe, report, receipt):
    inventory = json.loads(receipt.read_text(encoding="utf-8"))
    if inventory.get("admissionExitCode") != 0 or inventory.get("reportSHA256") != hashlib.sha256(report.read_bytes()).hexdigest():
        raise ValueError("Tool build requires successful unchanged OSV admission")
    lock_path = ROOT / "tools/security-toolchains" / tool / "Cargo.lock"
    digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    if digest != recipe["lockfileSHA256"]:
        raise ValueError("Tool lock differs from reviewed recipe")
    entries = [item for item in inventory["lockfiles"] if item["path"] == lock_path.relative_to(ROOT).as_posix() and item["sha256"] == digest]
    if len(entries) != 1:
        raise ValueError("Tool lock was not scanned")
    return lock_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("cargo-audit", "cargo-deny", "cargo-vet", "kani-verifier"))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    recipe = json.loads(RECIPES.read_text(encoding="utf-8"))[args.tool]
    lock_path = verify_admission(args.tool, recipe, args.report, args.receipt)
    version = recipe["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[0-9a-f]{64}", recipe["archiveSHA256"]):
        raise ValueError("Invalid reviewed tool version/checksum")
    spec = importlib.util.spec_from_file_location("osv_gate", ROOT / "scripts/osv-dependency-gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    request = urllib.request.Request(f"https://crates.io/api/v1/crates/{args.tool}/{version}/download", headers={"User-Agent": "Sunlit-security-tool-admission"})
    opener = urllib.request.build_opener(gate.HttpsRedirect())
    with opener.open(request, timeout=60) as response:
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != recipe["archiveSHA256"]:
        raise ValueError("Tool source archive size/checksum mismatch")
    cache = ROOT / ".cache/security-tools"
    source = cache / "src" / f"{args.tool}-{version}"
    for parent in (cache, cache.parent, source.parent, source, cache / "installed", cache / "installed/bin", ROOT / "target", ROOT / "target/security-tools"):
        if parent.is_symlink():
            raise ValueError("Tool source directories must not be symlinks")
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True)
    extract_source(data, source, f"{args.tool}-{version}/")
    vcs = json.loads((source / ".cargo_vcs_info.json").read_text(encoding="utf-8"))
    if vcs["git"]["sha1"] != recipe["sourceCommit"] or vcs["git"].get("dirty", False):
        raise ValueError("Tool source commit differs or is dirty")
    apply_manifest_edits(source, recipe.get("manifestVersionEdits", {}))
    shutil.copyfile(lock_path, source / "Cargo.lock")
    environment = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target/security-tools"))
    subprocess.run(["cargo", "install", "--locked", "--force", "--path", str(source), "--root", str(cache / "installed")], cwd=ROOT, env=environment, check=True, timeout=1200)
    if "GITHUB_PATH" in os.environ:
        with Path(os.environ["GITHUB_PATH"]).open("a", encoding="utf-8") as path:
            path.write(str(cache / "installed/bin") + "\n")
    binary = cache / "installed/bin" / (recipe["binary"] + (".exe" if os.name == "nt" else ""))
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("Expected installed tool binary is absent or a symlink")
    installed = {"sourceSHA256": recipe["archiveSHA256"], "lockfileSHA256": recipe["lockfileSHA256"], "binarySHA256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    (cache / "installed" / (args.tool + ".json")).write_text(json.dumps(installed, indent=2) + "\n", encoding="utf-8")
    print(f"Installed {args.tool} {version} from checksum-verified source and admitted frozen graph")


if __name__ == "__main__":
    main()

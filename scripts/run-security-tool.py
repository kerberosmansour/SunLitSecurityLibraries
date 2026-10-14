#!/usr/bin/env python3
"""Execute only the admitted source-built binary, bypassing PATH ambiguity."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("cargo-audit", "cargo-deny", "cargo-vet", "kani-verifier"))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("tool_installer", ROOT / "scripts/install-security-tool.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    recipe = json.loads(installer.RECIPES.read_text(encoding="utf-8"))[args.tool]
    installer.verify_admission(args.tool, recipe, args.report, args.receipt)
    directory = ROOT / ".cache/security-tools/installed"
    binary = directory / "bin" / (recipe["binary"] + (".exe" if os.name == "nt" else ""))
    record = json.loads((directory / (args.tool + ".json")).read_text(encoding="utf-8"))
    if binary.is_symlink() or record["sourceSHA256"] != recipe["archiveSHA256"] or record["lockfileSHA256"] != recipe["lockfileSHA256"] or record["binarySHA256"] != hashlib.sha256(binary.read_bytes()).hexdigest():
        raise ValueError("Installed tool no longer matches its admitted source build")
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ValueError("Cargo is required to run its verified subcommand")
    environment = dict(os.environ, CARGO=cargo)
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    # Cargo passes a subcommand prefix when invoking cargo-* executables.
    command = [str(binary), recipe["binary"].removeprefix("cargo-"), *arguments]
    # This is a trusted operator CLI, not a network-input handler. Only the
    # recipe-bound, digest-verified executable runs; arguments are never a shell.
    return subprocess.run(command, cwd=ROOT, env=environment, check=False, shell=False).returncode  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args


if __name__ == "__main__":
    raise SystemExit(main())

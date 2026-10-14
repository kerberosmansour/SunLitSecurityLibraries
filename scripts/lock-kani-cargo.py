#!/usr/bin/env python3
"""Give the repository-owned Kani installation a frozen Cargo wrapper."""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def lock_sdk(kani):
    link = kani / "toolchain"
    shadow = kani / "toolchain-locked"
    if shadow.exists():
        if link.resolve() != shadow.resolve():
            raise ValueError("Kani SDK wrapper already exists with a different binding")
        return
    if not link.is_symlink():
        raise ValueError("Expected the repository Kani installation to link its verified SDK")
    source = link.resolve(strict=True)
    cargo = source / "bin/cargo"
    digest = hashlib.sha256(cargo.read_bytes()).hexdigest()
    shadow.mkdir()
    for entry in source.iterdir():
        if entry.name != "bin":
            (shadow / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    (shadow / "bin").mkdir()
    for entry in (source / "bin").iterdir():
        if entry.name != "cargo":
            (shadow / "bin" / entry.name).symlink_to(entry)
    wrapper = shadow / "bin/cargo"
    shutil.copyfile(ROOT / "scripts/locked-cargo.py", wrapper)
    wrapper.chmod(0o755)
    (shadow / "bin/cargo.source.json").write_text(json.dumps({"path": str(cargo), "sha256": digest}, indent=2) + "\n", encoding="utf-8")
    # Replace only the symlink inside our repository cache, never the shared SDK.
    link.unlink()
    link.symlink_to(shadow, target_is_directory=True)


if __name__ == "__main__":
    lock_sdk(ROOT / ".cache/kani/kani-0.68.0")

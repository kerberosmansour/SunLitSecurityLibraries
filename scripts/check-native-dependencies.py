#!/usr/bin/env python3
"""Check the feature and build boundaries of the reviewed AWS-LC dependency batch."""
import json
import hashlib
from datetime import date, datetime, timezone
import os
import shutil
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import unittest
from unittest.mock import patch
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def read_metadata(target):
    return json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--all-features", "--format-version", "1", "--filter-platform", target], cwd=ROOT))


def check_boundary(metadata, environment, cargo_config):
    errors = []
    setting = cargo_config.get("env", {}).get("AWS_LC_SYS_USE_SYSTEM", {})
    if setting != {"value": "0", "force": True}:
        errors.append("Cargo must force AWS_LC_SYS_USE_SYSTEM=0 to build bundled AWS-LC")
    configured_environment = {}
    for key, configured in cargo_config.get("env", {}).items():
        value = configured.get("value") if isinstance(configured, dict) else configured
        if not isinstance(value, str):
            errors.append(f"Cargo environment override has an invalid value: {key}")
            continue
        # Cargo injects these values into native build children even though they
        # are not visible in this guard's own process environment.
        configured_environment[key] = value
    for key, value in [*environment.items(), *configured_environment.items()]:
        upper = key.upper()
        if upper.startswith("AWS_LC_SYS_SYSTEM_"):
            errors.append(f"External native implementation override is forbidden: {key}")
        if upper.startswith("AWS_LC_SYS_USE_SYSTEM") and value != "0":
            errors.append(f"System discovery override is forbidden: {key}")
    packages = metadata.get("packages", [])
    names = {package["id"]: package["name"] for package in packages}
    for package in packages:
        accepted = {"lru": "0.18.3", "xxhash-rust": "0.8.15", "redis": "1.2.1", "aws-config": "1.8.16", "aws-sdk-kms": "1.106.0", "aws-sdk-sts": "1.103.0", "aws-smithy-json": "0.62.7", "aws-smithy-schema": "0.1.0", "aws-smithy-runtime-api": "1.12.3", "aws-smithy-types": "1.4.9"}.get(package["name"])
        if accepted is not None and package["version"] != accepted:
            errors.append(f"{package['name']} version outside the reviewed hold boundary: {package['version']}")
    for node in metadata.get("resolve", {}).get("nodes", []):
        name = names.get(node["id"])
        features = set(node.get("features", []))
        forbidden = features & ({"legacy-des", "fips"} if name == "aws-lc-rs" else {"fips", "ssl"} if name == "aws-lc-sys" else set())
        if forbidden:
            errors.append(f"{name} features outside the reviewed boundary: {', '.join(sorted(forbidden))}")
    return errors


def check_exceptions(exceptions, packages, today):
    errors = []
    for exception in exceptions:
        name = exception["package"]
        versions = {package["version"] for package in packages if package["name"] == name}
        if versions != {exception["version"]}:
            errors.append(f"Maintenance exception for {name} does not match its exact resolved version")
        try:
            expiry = date.fromisoformat(exception["expires"])
        except (KeyError, ValueError):
            errors.append(f"Maintenance exception for {name} needs a valid expiry")
            continue
        if not exception.get("owner"):
            errors.append(f"Maintenance exception for {name} needs an owner")
        if today >= expiry:
            errors.append(f"Maintenance exception for {name} expired on {expiry}")
    return errors


def check_formatter():
    formatter = shutil.which("rustfmt")
    rustup = shutil.which("rustup")
    if formatter is None or rustup is None:
        return ["A trusted rustup-managed rustfmt is required for generated atom tables"]
    expected = Path(subprocess.check_output([rustup, "which", "rustfmt"], text=True).strip()).resolve()
    selected = Path(formatter).resolve()
    # rustfmt normally resolves through the rustup proxy. Accept that proxy
    # or the exact selected toolchain executable, then verify dispatch.
    anchor = Path(rustup).resolve()
    same_proxy = os.path.samefile(selected, anchor)
    # Windows proxies can be copies instead of links. Require identical bytes
    # in the same rustup-managed bin directory before invoking that copy.
    copied_proxy = selected.parent == anchor.parent and hashlib.sha256(selected.read_bytes()).digest() == hashlib.sha256(anchor.read_bytes()).digest()
    if selected != expected and not same_proxy and not copied_proxy:
        return ["PATH selects a formatter outside the selected rustup toolchain"]
    actual_version = subprocess.check_output([formatter, "--version"], text=True).strip()
    expected_version = subprocess.check_output([str(expected), "--version"], text=True).strip()
    if actual_version != expected_version:
        return ["rustfmt proxy does not dispatch to the selected toolchain"]
    return []


class NativeBoundaryTests(unittest.TestCase):
    def test_metadata_uses_utf8_independent_of_windows_locale(self):
        payload = json.dumps({"packages": [], "description": "smart quotes \u201d"}, ensure_ascii=False).encode("utf-8")
        def output(*_args, **options):
            return payload.decode(options.get("encoding", "cp1252")) if options.get("text") else payload
        with patch("subprocess.check_output", side_effect=output):
            self.assertEqual(read_metadata("x86_64-pc-windows-msvc")["description"], "smart quotes \u201d")

    def test_unknown_formatter_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory(prefix="sunlit-formatter-test-") as directory:
            executable = Path(directory) / ("rustfmt.exe" if os.name == "nt" else "rustfmt")
            marker = Path(directory) / "executed"
            executable.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
            executable.chmod(0o700)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                self.assertTrue(any("outside" in error for error in check_formatter()))
            self.assertFalse(marker.exists())

    def test_exception_expires_and_cannot_cover_a_different_version(self):
        exceptions = [{"package": "vendor", "version": "1", "owner": "maintainer", "expires": "2026-11-14"}]
        packages = [{"name": "vendor", "version": "1"}]
        self.assertEqual(check_exceptions(exceptions, packages, date(2026, 11, 13)), [])
        self.assertTrue(any("expired" in error for error in check_exceptions(exceptions, packages, date(2026, 11, 14))))
        self.assertTrue(any("exact" in error for error in check_exceptions(exceptions, [{"name": "vendor", "version": "2"}], date(2026, 10, 14))))

    def test_repository_selects_bundled_source(self):
        config = tomllib.loads((ROOT / ".cargo/config.toml").read_text(encoding="utf-8"))
        self.assertEqual(check_boundary({}, {}, config), [])

    def test_optional_des_feature_is_rejected(self):
        metadata = {"packages": [{"id": "crypto", "name": "aws-lc-rs"}], "resolve": {"nodes": [{"id": "crypto", "features": ["legacy-des"]}]}}
        config = {"env": {"AWS_LC_SYS_USE_SYSTEM": {"value": "0", "force": True}}}
        self.assertTrue(any("legacy-des" in error for error in check_boundary(metadata, {}, config)))

    def test_nonforced_config_cannot_hide_process_override(self):
        config = {"env": {"AWS_LC_SYS_USE_SYSTEM": {"value": "0", "force": True}, "AWS_LC_SYS_USE_SYSTEM_aarch64_apple_darwin": "0"}}
        self.assertTrue(check_boundary({}, {"AWS_LC_SYS_USE_SYSTEM_aarch64_apple_darwin": "1"}, config))

    def test_cargo_config_target_override_cannot_bypass_native_guard(self):
        config = {"env": {"AWS_LC_SYS_USE_SYSTEM": {"value": "0", "force": True}, "AWS_LC_SYS_USE_SYSTEM_aarch64_apple_darwin": {"value": "1", "force": True}}}
        self.assertTrue(check_boundary({}, {}, config))
        config["env"].pop("AWS_LC_SYS_USE_SYSTEM_aarch64_apple_darwin")
        config["env"]["AWS_LC_SYS_SYSTEM_DIR"] = "/unreviewed"
        self.assertTrue(check_boundary({}, {}, config))

    def test_target_override_cannot_reenable_discovery(self):
        config = {"env": {"AWS_LC_SYS_USE_SYSTEM": {"value": "0", "force": True}}}
        self.assertTrue(check_boundary({}, {"AWS_LC_SYS_USE_SYSTEM_aarch64_apple_darwin": "1"}, config))
        self.assertTrue(check_boundary({}, {"AWS_LC_SYS_SYSTEM_DIR": "/unreviewed"}, config))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        unittest.main(argv=[sys.argv[0]])
    else:
        host = subprocess.check_output(["rustc", "-vV"], text=True)
        target = re.search(r"^host: (.+)$", host, re.MULTILINE).group(1)
        metadata = read_metadata(target)
        config = tomllib.loads((ROOT / ".cargo/config.toml").read_text(encoding="utf-8"))
        exceptions = json.loads((ROOT / "supply-chain/maintenance-exceptions.json").read_text(encoding="utf-8"))["exceptions"]
        new_api_use = any(re.search(r"aws_smithy_(schema|json\s*::\s*(codec|protocol))", source.read_text(encoding="utf-8")) for source in (ROOT / "crates").rglob("*.rs"))
        review_errors = ["New AWS schema/codec adoption requires review before the legacy-SDK exceptions can apply"] if new_api_use else []
        errors = review_errors + check_boundary(metadata, os.environ, config) + check_formatter() + check_exceptions(exceptions, metadata["packages"], datetime.now(timezone.utc).date())
        if errors:
            print("\n".join(errors), file=sys.stderr)
            sys.exit(1)
        print("Dependency feature, native build, formatter and exception boundaries verified for " + target)

"""Runtime-relevant CI boundary tests using generated SDK/report fixtures."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

cargo = module("locked", "locked-cargo.py")
kani = module("kani", "lock-kani-cargo.py")
dast = module("dast", "check-dast-report.py")

class IntegrationTests(unittest.TestCase):
    def test_cargo_wrapper_locks_metadata_and_build_without_changing_arguments(self):
        self.assertEqual(cargo.locked_arguments(["metadata", "--format-version", "1"]), ["metadata", "--locked", "--format-version", "1"])
        self.assertEqual(cargo.locked_arguments(["+nightly", "rustc", "-p", "secure_data"]), ["+nightly", "rustc", "--locked", "-p", "secure_data"])
        self.assertEqual(cargo.locked_arguments(["build", "--locked"]), ["build", "--locked"])
        self.assertEqual(cargo.locked_arguments(["--version"]), ["--version"])
        self.assertEqual(cargo.locked_arguments(["--quiet", "metadata", "--format-version", "1"]), ["--quiet", "metadata", "--locked", "--format-version", "1"])
        self.assertEqual(cargo.locked_arguments(["run", "--", "--locked"]), ["run", "--locked", "--", "--locked"])
        self.assertEqual(cargo.locked_arguments(["--config", "build", "metadata"]), ["--config", "build", "metadata", "--locked"])

    def test_sdk_shadow_does_not_modify_shared_sdk_and_delegates_locked(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            sdk = root / "original-sdk";sdk.mkdir();(sdk / "bin").mkdir();(sdk / "lib").mkdir()
            binary = sdk / "bin/cargo"
            binary.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n');binary.chmod(0o755)
            original = binary.read_bytes()
            installation = root / "kani";installation.mkdir();(installation / "toolchain").symlink_to(sdk, target_is_directory=True)
            kani.lock_sdk(installation)
            self.assertEqual(binary.read_bytes(), original)
            result = subprocess.check_output([str(installation / "toolchain/bin/cargo"), "metadata", "--format-version", "1"], text=True)
            self.assertEqual(json.loads(result), ["metadata", "--locked", "--format-version", "1"])
            binary.write_text("modified SDK")
            failed = subprocess.run([str(installation / "toolchain/bin/cargo"), "--version"], capture_output=True)
            self.assertNotEqual(failed.returncode, 0)

    def test_missing_or_malformed_scan_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "report.xml"
            with self.assertRaises(ValueError):dast.check_report(p)
            for text in ('<unexpected/>', '<testsuites/>', '<testsuite/>', '<testsuites><unexpected/></testsuites>'):
                p.write_text(text)
                with self.assertRaises(ValueError):dast.check_report(p)

    def test_report_distinguishes_empty_clean_scan_and_findings(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "report.xml"
            p.write_text('<testsuite tests="0" failures="0" errors="0"/>')
            self.assertFalse(dast.check_report(p))
            p.write_text('<testsuite tests="1" failures="1" errors="0"><testcase><failure message="generated"/></testcase></testsuite>')
            self.assertTrue(dast.check_report(p))
            p.write_text('<testsuites><testsuite tests="1" failures="1" errors="0"/></testsuites>')
            self.assertTrue(dast.check_report(p))

if __name__ == "__main__":unittest.main()

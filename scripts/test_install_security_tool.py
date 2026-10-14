"""Source-admission integrity tests: generated archives, no downloads/builds."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("tools", Path(__file__).with_name("install-security-tool.py"))
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)

class ToolSourceTests(unittest.TestCase):
    def archive(self, name, link=False):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            member = tarfile.TarInfo(name)
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
                archive.addfile(member)
            else:
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        return data.getvalue()

    def test_traversal_and_symlink_sources_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for name, link in (("tool-1/../../outside", False), ("other/file", False), ("tool-1/link", True)):
                with self.assertRaises(ValueError):
                    tools.extract_source(self.archive(name, link), Path(folder), "tool-1/")

    def test_manifest_overlay_is_exact_and_standalone(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Cargo.toml").write_text('[package]\nname="generated"\nversion="1.0.0"\n[dependencies.reqwest]\nversion = "0.11.10"\n')
            tools.apply_manifest_edits(root, {"reqwest": {"from": "0.11.10", "to": "=0.12.28"}})
            data = tools.tomllib.loads((root / "Cargo.toml").read_text())
            self.assertEqual(data["dependencies"]["reqwest"]["version"], "=0.12.28")
            self.assertIn("workspace", data)
            with self.assertRaisesRegex(ValueError, "exactly once"):
                tools.apply_manifest_edits(root, {"reqwest": {"from": "0.11.10", "to": "=0.12.28"}})

    def test_recipe_and_admission_receipt_must_bind_same_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            lock = root / "tools/security-toolchains/cargo-vet/Cargo.lock"
            lock.parent.mkdir(parents=True)
            lock.write_bytes(b"reviewed")
            report = root / "report.json";report.write_bytes(b'{}')
            digest = hashlib.sha256(lock.read_bytes()).hexdigest()
            receipt = root / "receipt.json"
            data = {"admissionExitCode": 0, "reportSHA256": hashlib.sha256(report.read_bytes()).hexdigest(), "lockfiles": [{"path": "tools/security-toolchains/cargo-vet/Cargo.lock", "sha256": digest}]}
            receipt.write_text(json.dumps(data))
            with patch.object(tools, "ROOT", root):
                self.assertEqual(tools.verify_admission("cargo-vet", {"lockfileSHA256": digest}, report, receipt), lock)
                lock.write_bytes(b"modified")
                with self.assertRaisesRegex(ValueError, "reviewed recipe"):
                    tools.verify_admission("cargo-vet", {"lockfileSHA256": digest}, report, receipt)

if __name__ == "__main__":
    unittest.main()

"""Generated release archives; no dependency install or crate execution."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("release_gate", Path(__file__).with_name("admit-release-package.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        targets={"lib":[{"name":"security_core","path":"src/lib.rs"}], "bin":[], "test":[], "example":[], "bench":[]}
        self.target_patch=patch.object(release,"source_targets",return_value=targets)
        self.target_patch.start();self.addCleanup(self.target_patch.stop)

    def fixture(self, root, *, checksum="0"*64, injected=False, bad_source=False, build=False, dirty=False, dep_path=False, changed_target=False, path_only_dev=False):
        crate = root / "crates/security_core"; (crate / "src").mkdir(parents=True)
        original = '[package]\nname="security_core"\nversion="0.2.1"\n[dependencies]\nfixture_dep="=1.0.0"\n'
        if path_only_dev: original += '[dev-dependencies]\nlocal_dev={path="../local_dev"}\n'
        (crate / "Cargo.toml").write_text(original)
        (crate / "src/lib.rs").write_text("pub fn fixture() {}\n")
        (root / "Cargo.toml").write_text('[workspace]\nmembers=["crates/security_core"]\n[workspace.dependencies]\n')
        lock = 'version=3\n[[package]]\nname="security_core"\nversion="0.2.1"\n[[package]]\nname="fixture_dep"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + "0"*64 + '"\n'
        (root / "Cargo.lock").write_text(lock)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.name=SLO Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "synthetic"], cwd=root, check=True)
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        normalized = original.replace('[dependencies]', ('build=true\n' if build else 'build=false\n')+'[lib]\npath="src/lib.rs"\n[dependencies]')
        if path_only_dev: normalized=normalized.split('[dev-dependencies]')[0]
        if dep_path: normalized=normalized.replace('fixture_dep="=1.0.0"','fixture_dep={version="=1.0.0",path="injected"}')
        if changed_target: normalized=normalized.replace('path="src/lib.rs"','path="Cargo.toml.orig"')
        packaged_lock=lock.replace('checksum="'+"0"*64+'"','checksum="'+checksum+'"')
        if injected: packaged_lock+='[[package]]\nname="unexpected"\nversion="1.0.0"\n'
        files = {"Cargo.toml.orig":original, "Cargo.toml":normalized, "Cargo.lock":packaged_lock, ".cargo_vcs_info.json":json.dumps({"git":{"sha1":commit,"dirty":dirty},"path_in_vcs":"crates/security_core"}), "src/lib.rs":"pub fn injected() {}\n" if bad_source else "pub fn fixture() {}\n"}
        archive=root / "security_core-0.2.1.crate"
        with tarfile.open(archive,"w:gz") as tar:
            for name,value in files.items():
                data=value.encode();member=tarfile.TarInfo("security_core-0.2.1/"+name);member.size=len(data);tar.addfile(member,io.BytesIO(data))
        return archive,commit

    def test_exact_source_checksum_subset_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);archive,commit=self.fixture(root)
            name,version,lock,digest=release.candidate(archive,root,commit,{})
            self.assertEqual((name,version),("security_core","0.2.1"));self.assertIn(b"fixture_dep",lock)

    def test_unknown_transitive_package_or_changed_checksum_is_rejected(self):
        for options in ({"injected":True},{"checksum":"f"*64}):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);archive,commit=self.fixture(root,**options)
                with self.assertRaisesRegex(ValueError,"dependency|provenance"):
                    release.candidate(archive,root,commit,{})

    def test_source_substitution_or_build_authority_or_dirty_vcs_is_rejected(self):
        for options in ({"bad_source":True},{"build":True},{"dirty":True}):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);archive,commit=self.fixture(root,**options)
                with self.assertRaises(ValueError):release.candidate(archive,root,commit,{})

    def test_path_only_dev_dependency_is_removed_by_cargo_normalization(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);archive,commit=self.fixture(root,path_only_dev=True)
            release.candidate(archive,root,commit,{})

    def test_injected_dependency_path_or_redirected_target_is_rejected(self):
        for options in ({"dep_path":True},{"changed_target":True}):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);archive,commit=self.fixture(root,**options)
                with self.assertRaises(ValueError):release.candidate(archive,root,commit,{})

    def test_archive_replacement_cannot_inherit_reviewed_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);archive,commit=self.fixture(root)
            _,_,_,digest=release.candidate(archive,root,commit,{})
            release.verify_unchanged_archive(archive,digest)
            archive.write_bytes(b"replaced archive")
            with self.assertRaisesRegex(ValueError,"changed during admission"):
                release.verify_unchanged_archive(archive,digest)

    def test_workspace_dependency_features_are_merged_before_comparison(self):
        workspace={"workspace":{"dependencies":{"example":{"version":"1","features":["a"],"path":"../example"}}}}
        inherited={"dependencies":{"example":{"workspace":True,"features":["b"]}}}
        normalized={"dependencies":{"example":{"version":"1","features":["b","a"]}}}
        self.assertEqual(release.normalized_dependencies(inherited,workspace),release.normalized_dependencies(normalized,workspace))

if __name__ == "__main__":unittest.main()

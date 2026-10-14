"""Release integrity regressions; no network or real crate execution."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest

spec = importlib.util.spec_from_file_location('release_artifacts', Path(__file__).with_name('prepare-release-artifacts.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SOURCE = 'a' * 40


def fixture(mode=0o644, source=SOURCE, version='0.2.0', duplicate_root=False, wrong_source=False):
    contents = {
        '.cargo_vcs_info.json': json.dumps({'git': {'sha1': source}}),
        'Cargo.toml': f'[package]\nname="sample"\nversion="{version}"\nlicense="MIT"\n',
        'Cargo.lock': 'version=4\n[[package]]\nname="sample"\nversion="0.2.0"\ndependencies=["serde"]\n[[package]]\nname="serde"\nversion="1.0.0"\nchecksum="' + 'b' * 64 + '"\n',
    }
    if duplicate_root:
        contents['Cargo.lock'] += '\n[[package]]\nname="sample"\nversion="0.2.0"\n'
    if wrong_source:
        contents['Cargo.lock'] = contents['Cargo.lock'].replace('dependencies=["serde"]', 'dependencies=["serde 1.0.0 (registry+https://other.example/index)"]')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, text in contents.items():
            data = text.encode(); info = tarfile.TarInfo('sample-0.2.0/' + name)
            info.size = len(data); info.mode = mode
            archive.addfile(info, io.BytesIO(data))
    data = output.getvalue()
    return data, {'name': 'sample', 'version': '0.2.0', 'checksum': hashlib.sha256(data).hexdigest()}


class ReleaseIntegrityTests(unittest.TestCase):
    def test_bom_binds_registered_archive_and_exact_lock_graph(self):
        data, record = fixture(); bom = release.verified_bom(data, record, SOURCE)
        self.assertEqual(bom['metadata']['component']['hashes'][0]['content'], record['checksum'])
        self.assertEqual(bom['dependencies'], [{'ref': 'pkg:cargo/sample@0.2.0', 'dependsOn': ['pkg:cargo/serde@1.0.0']}, {'ref': 'pkg:cargo/serde@1.0.0', 'dependsOn': []}])

    def test_same_file_content_repacked_with_other_modes_is_not_accepted(self):
        _, record = fixture(mode=0o644); repacked, _ = fixture(mode=0o600)
        with self.assertRaisesRegex(ValueError, 'checksum'):
            release.verified_bom(repacked, record, SOURCE)

    def test_duplicate_root_lock_entries_cannot_be_accepted(self):
        data, record = fixture(duplicate_root=True)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            release.verified_bom(data, record, SOURCE)

    def test_dependency_source_qualifier_must_match_the_lock(self):
        data, record = fixture(wrong_source=True)
        with self.assertRaisesRegex(ValueError, 'resolved exactly'):
            release.verified_bom(data, record, SOURCE)

    def test_different_source_commit_cannot_be_signed(self):
        data, record = fixture(source='c' * 40)
        with self.assertRaisesRegex(ValueError, 'source'):
            release.verified_bom(data, record, SOURCE)

    def test_different_manifest_version_cannot_be_signed(self):
        data, record = fixture(version='0.3.0')
        with self.assertRaisesRegex(ValueError, 'identity'):
            release.verified_bom(data, record, SOURCE)


if __name__ == '__main__':
    unittest.main()

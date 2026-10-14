#!/usr/bin/env python3
"""Retrieve checksum-approved registry packages; never rebuild or execute them."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


def verified_bom(data, record, source_commit):
    checksum = hashlib.sha256(data).hexdigest()
    if checksum != record['checksum']:
        raise ValueError('Registry archive does not match the approved checksum')
    prefix = f"{record['name']}-{record['version']}/"
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        def read(name):
            member = archive.getmember(prefix + name)
            if not member.isfile():
                raise ValueError('Package metadata must be regular files')
            return archive.extractfile(member).read().decode('utf-8')
        vcs = json.loads(read('.cargo_vcs_info.json'))
        manifest = tomllib.loads(read('Cargo.toml'))
        lock = tomllib.loads(read('Cargo.lock'))
    if vcs['git']['sha1'] != source_commit or vcs['git'].get('dirty', False):
        raise ValueError('Package source does not match the approved clean commit')
    package = manifest['package']
    if (package['name'], package['version']) != (record['name'], record['version']):
        raise ValueError('Package identity differs from the approved record')
    packages = lock['package']
    by_name = {}
    for item in packages:
        by_name.setdefault(item['name'], []).append(item)
    ref = lambda item: f"pkg:cargo/{item['name']}@{item['version']}"
    root_ref = ref(record)
    components, dependencies = [], []
    for item in packages:
        identity = ref(item)
        if identity != root_ref:
            component = {'type': 'library', 'bom-ref': identity, 'name': item['name'], 'version': item['version'], 'purl': identity}
            if item.get('checksum'):
                component['hashes'] = [{'alg': 'SHA-256', 'content': item['checksum']}]
            components.append(component)
        refs = []
        for dependency in item.get('dependencies', []):
            tokens = dependency.split(' ')
            matches = by_name.get(tokens[0], [])
            if len(tokens) > 1:
                matches = [candidate for candidate in matches if candidate['version'] == tokens[1]]
            if len(matches) != 1:
                raise ValueError('Packaged lock dependency cannot be resolved exactly')
            refs.append(ref(matches[0]))
        dependencies.append({'ref': identity, 'dependsOn': sorted(set(refs))})
    component_refs = [component['bom-ref'] for component in components]
    if len(component_refs) != len(set(component_refs)):
        raise ValueError('Duplicate dependency identities require source-aware review')
    if root_ref not in {entry['ref'] for entry in dependencies}:
        raise ValueError('Packaged lock is missing the released library')
    root = {'type': 'library', 'bom-ref': root_ref, 'name': record['name'], 'version': record['version'], 'purl': root_ref, 'hashes': [{'alg': 'SHA-256', 'content': checksum}]}
    if package.get('license'):
        root['licenses'] = [{'expression': package['license']}]
    return {'$schema': 'https://cyclonedx.org/schema/bom-1.6.schema.json', 'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': root, 'properties': [
                {'name': 'cdx:sunlit:dependency-scope', 'value': 'Exact packaged Cargo.lock; optional, development and target dependencies retained. Not a runtime-only inventory or vulnerability audit.'},
                {'name': 'cdx:sunlit:source-commit', 'value': source_commit}]},
            'components': sorted(components, key=lambda item: item['bom-ref']), 'dependencies': sorted(dependencies, key=lambda item: item['ref'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--crate', default='all')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifests = [tomllib.loads(path.read_text(encoding='utf-8'))['package'] for path in (ROOT / 'crates').glob('*/Cargo.toml')]
    libraries = {item['name']: item['version'] for item in manifests if item.get('publish') is not False}
    versions = set(libraries.values())
    if len(versions) != 1:
        raise ValueError('Release library versions must agree')
    version = versions.pop()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Release version must be stable semver')
    approved_path = ROOT / f'declarations/release-{version}-packages.json'
    approved = json.loads(approved_path.read_text(encoding='utf-8'))
    records = {record['name']: record for record in approved['packages']}
    if approved.get('formatVersion') != 1 or approved['version'] != version or set(records) != set(libraries) or len(records) != len(approved['packages']):
        raise ValueError('Approved manifest must cover the exact public library set')
    source_commit = approved['sourceCommit']
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('Approved source commit must be exact')
    # The calling workflow checks main ancestry; this also validates the
    # approved source against the checkout without running package code.
    import subprocess
    subprocess.run(['git', 'merge-base', '--is-ancestor', source_commit, 'origin/main'], cwd=ROOT, check=True)
    selected = sorted(records) if args.crate == 'all' else [args.crate]
    if any(name not in records for name in selected):
        raise ValueError('Unknown release crate')
    args.output.mkdir(parents=True, exist_ok=False)
    for name in selected:
        record = records[name]
        if record['version'] != version or not re.fullmatch(r'[a-z][a-z0-9_]*', name) or not re.fullmatch(r'[0-9a-f]{64}', record['checksum']):
            raise ValueError('Invalid approved package identity/checksum')
        request = urllib.request.Request(f'https://crates.io/api/v1/crates/{name}/{version}/download', headers={'User-Agent': 'SunLitSecurityLibraries-release-verification/' + version})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_BYTES:
            raise ValueError('Registry archive exceeds the release bound')
        bom = verified_bom(data, record, source_commit)
        (args.output / f'{name}-{version}.crate').write_bytes(data)
        (args.output / f'sbom-{name}-{version}.cdx.json').write_text(json.dumps(bom, indent=2) + '\n', encoding='utf-8')
        print(f'{name}: exact published bytes and source verified; SBOM prepared')
    (args.output / approved_path.name).write_bytes(approved_path.read_bytes())
    (args.output / 'cyclonedx-1.6-capabilities.json').write_bytes((ROOT / 'declarations/cyclonedx-1.6-capabilities.json').read_bytes())
    hashes = ''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in sorted(args.output.iterdir()) if path.is_file())
    (args.output / 'SHA256SUMS').write_text(hashes, encoding='utf-8')


if __name__ == '__main__':
    main()

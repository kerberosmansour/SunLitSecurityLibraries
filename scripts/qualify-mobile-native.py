#!/usr/bin/env python3
"""Build/run generated mobile qualification with installed vendor SDKs only."""
import argparse
import hmac
import json
import os
import plistlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ANDROID_SDK = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or Path.home() / 'Library/Android/sdk')
PACKAGE = 'com.sunlit.securedata.qualification'
IOS_PACKAGE = PACKAGE + '.ios'


def run(arguments, **kwargs):
    return subprocess.run([str(a) for a in arguments], check=True, timeout=120, shell=False, **kwargs)


def android_owner(device, ownership):
    if not re.fullmatch(r'emulator-[0-9]+', device) or ownership is None:
        raise ValueError('A receipt for a separately created task-owned emulator is required')
    if ownership.is_symlink() or ownership.stat().st_size > 4096:
        raise ValueError('Invalid emulator ownership receipt')
    receipt = json.loads(ownership.read_text())
    data = Path(receipt['dataDirectory'])
    if data.is_symlink() or data.resolve() != ownership.resolve().parent / 'emulator-data':
        raise ValueError('Emulator data directory is outside its isolated qualification directory')
    pid = receipt['pid']; token = receipt['ownerToken']
    if receipt['serial'] != device or type(pid) is not int or pid <= 0 or not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('Invalid emulator owner identity')
    # Positive integer PID, fixed executable/options, no shell or option text.
    command = subprocess.check_output(['ps', '-p', str(pid), '-o', 'command='], text=True, timeout=10)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
    if 'qemu-system' not in command or str(ANDROID_SDK / 'emulator') not in command or str(data) not in command or '-port ' + device.removeprefix('emulator-') not in command:
        raise ValueError('Live emulator does not match the created task instance')
    # Device is emulator-[0-9]+; SDK executable and remote command/property are
    # fixed, and no receipt field becomes executable or device-shell syntax.
    live = subprocess.check_output([str(ANDROID_SDK / 'platform-tools/adb'), '-s', device, 'shell', 'getprop', 'debug.sunlit.qualification_owner'], text=True, timeout=10).strip()  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
    if not hmac.compare_digest(live, token):
        raise ValueError('Live emulator ownership token differs')
    return ownership.resolve().parent


def android_phase(adb, device, phase):
    run([adb, '-s', device, 'shell', 'am', 'force-stop', PACKAGE])
    run([adb, '-s', device, 'shell', 'run-as', PACKAGE, 'rm', '-f', 'files/qualification-result.json'])
    # adb shell joins remote arguments into shell text; quote the fixed nested
    # class name so its dollar sign is not expanded by the device shell.
    component = "'" + PACKAGE + "/com.sunlit.securedata.mobile.QualificationActivity$Runner'"
    run([adb, '-s', device, 'shell', 'am', 'instrument', '-w', '-e', 'phase', phase, component])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = subprocess.run([str(adb), '-s', device, 'shell', 'run-as', PACKAGE, 'cat', 'files/qualification-result.json'], capture_output=True, timeout=5, shell=False)
        if result.returncode == 0:
            if len(result.stdout) > 8192:
                raise ValueError('Native qualification report exceeds bound')
            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError:
                # The Activity may still be writing this run's fresh file.
                # Retry only within the same deadline; malformed final reports
                # never become a passing result.
                time.sleep(1)
                continue
            if not isinstance(report, dict) or report.get('status') not in ('pass', 'fail'):
                raise ValueError('Invalid native qualification report')
            return dict(report, phase=phase)
        time.sleep(1)
    raise ValueError('Native qualification report timed out')


def android(output, device, ownership=None, fault_injection=False):
    # Overwrite a previous result before any build/device operation. Every exit
    # publishes this run's terminal state, including ownership/build failures.
    report = {'runId': str(uuid.uuid4()), 'status': 'fail', 'platform': 'android', 'phases': [], 'cleanup': {'status': 'not_attempted'}}
    report_path = output / 'report.json'
    if report_path.is_symlink():
        raise ValueError('Qualification report cannot be a symlink')
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    install_attempted = False
    adb = ANDROID_SDK / 'platform-tools/adb'
    try:
        owned = android_owner(device, ownership)
        jar = ANDROID_SDK / 'platforms/android-36/android.jar'
        tools = ANDROID_SDK / 'build-tools/36.1.0'
        sources = ROOT / 'crates/secure_data/native/android'
        classes = output / 'classes'; classes.mkdir(exist_ok=True)
        dex = output / 'dex'; dex.mkdir(exist_ok=True)
        bridge_source = sources / 'MobileKeyBridge.java'
        if fault_injection:
            before, unwrap = bridge_source.read_text().split('    public Unwrapped unwrap(', 1)
            substitutions = {'FileLock lock=channel.tryLock()': 'FileLock lock=QualificationActivity.qualificationLock(channel.tryLock())', 'data=cipher.doFinal(frame,13,48);': 'data=QualificationActivity.qualificationObserve(cipher.doFinal(frame,13,48));'}
            for original, replacement in substitutions.items():
                if unwrap.count(original) != 1:
                    raise ValueError('Fault fixture does not match the reviewed unwrap boundary')
                unwrap = unwrap.replace(original, replacement)
            bridge_source = output / 'MobileKeyBridge.java'
            bridge_source.write_text(before + '    public Unwrapped unwrap(' + unwrap)
        run(['javac', '--release', '17', '-cp', jar, '-d', classes, bridge_source, sources / 'QualificationActivity.java'])
        run([tools / 'd8', '--lib', jar, '--min-api', '31', '--output', dex, *sorted(classes.rglob('*.class'))])
        unsigned = output / 'unsigned.apk'
        run([tools / 'aapt2', 'link', '--manifest', sources / 'AndroidManifest.xml', '-I', jar, '-o', unsigned])
        with zipfile.ZipFile(unsigned, 'a') as archive:
            archive.write(dex / 'classes.dex', 'classes.dex')
        key = owned / 'fixture-signing.p12'
        if not key.exists():
            run(['keytool', '-genkeypair', '-alias', 'generated-fixture', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '1', '-dname', 'CN=Generated Qualification', '-storetype', 'PKCS12', '-keystore', key, '-storepass', 'fixture-only', '-keypass', 'fixture-only'])
        apk = output / 'qualification.apk'
        run([tools / 'apksigner', 'sign', '--ks', key, '--ks-key-alias', 'generated-fixture', '--ks-pass', 'pass:fixture-only', '--out', apk, unsigned])
        # Recheck the live instance immediately before the first mutation.
        android_owner(device, ownership)
        install_attempted = True
        run([adb, '-s', device, 'install', '-r', apk])
        # Validated numeric emulator serial, fixed SDK executable/component and
        # fixed remote command; this probes rejection, never interpolates input.
        external = subprocess.run([str(adb), '-s', device, 'shell', 'am', 'start', '-W', '-n', PACKAGE + '/com.sunlit.securedata.mobile.QualificationActivity'], capture_output=True, timeout=15, shell=False)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        if b'not exported' not in external.stdout + external.stderr:
            raise ValueError('Qualification control Activity is externally accessible')
        report['externalActivityLaunch'] = 'denied'
        phases = ('persistence_failure', 'seed', 'recover') + (('close_failure',) if fault_injection else ()) + ('tamper', 'invalidate', 'recover_deleted')
        for phase in phases:
            result = android_phase(adb, device, phase)
            report['phases'].append(result)
            if result['status'] != 'pass':
                raise ValueError('Native qualification assertion failed')
        report['status'] = 'pass'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report['status'] = 'fail'
        report['error'] = type(error).__name__  # no native details or key values
    finally:
        if install_attempted:
            try:
                android_owner(device, ownership)
                cleanup = android_phase(adb, device, 'cleanup')
                report['cleanup'] = cleanup
                if cleanup['status'] != 'pass':
                    report['status'] = 'fail'
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                report['cleanup'] = {'status': 'fail', 'error': type(error).__name__}
                report['status'] = 'fail'
            # App removal is a second cleanup layer; Android removes its keys.
            # If the device is lost, the failed cleanup remains explicit.
            try:
                android_owner(device, ownership)
                run([adb, '-s', device, 'uninstall', PACKAGE])
                report['cleanup']['appRemoved'] = True
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                report['cleanup']['appRemoved'] = False
                report['status'] = 'fail'
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['status'] == 'pass' else 1


def ios_owner(device, ownership):
    if ownership is None or ownership.is_symlink() or ownership.stat().st_size > 4096:
        raise ValueError('A task-created simulator ownership receipt is required')
    receipt = json.loads(ownership.read_text())
    uuid.UUID(device)
    if receipt['deviceUDID'] != device or not receipt['name'].startswith('SunlitNative-') or not re.fullmatch(r'[0-9a-f]{64}', receipt['ownerToken']):
        raise ValueError('Invalid simulator owner identity')
    uuid.UUID(receipt['name'].removeprefix('SunlitNative-'))
    devices = json.loads(subprocess.check_output(['xcrun', 'simctl', 'list', 'devices', '--json'], timeout=30))['devices']
    matching = [entry for entry in devices.get(receipt['runtime'], []) if entry['udid'] == device]
    if len(matching) != 1 or matching[0]['name'] != receipt['name'] or matching[0]['state'] != 'Booted':
        raise ValueError('Live simulator differs from the created task instance')
    live = subprocess.check_output(['xcrun', 'simctl', 'getenv', device, 'SUNLIT_NATIVE_OWNER'], text=True, timeout=10).strip()
    if not hmac.compare_digest(live, receipt['ownerToken']):
        raise ValueError('Live simulator ownership token differs')


def ios_project(output):
    """Generate a vendor-only Xcode target; no scripts or package references."""
    sources = ROOT / 'crates/secure_data/native/ios'
    entitlements = output / 'simulator-entitlements.plist'
    entitlements.write_bytes(plistlib.dumps({'application-identifier': 'SUNLITTEST.' + IOS_PACKAGE, 'keychain-access-groups': ['SUNLITTEST.' + IOS_PACKAGE]}))
    project = output / 'NativeQualification.xcodeproj'; project.mkdir(exist_ok=True)
    identity = lambda number: f'{number:024X}'
    bridge, qualification, product, group, products, phase, target, root, configs, config, project_configs, project_config, bridge_build, qualification_build = map(identity, range(1, 15))
    quote = json.dumps
    settings = {'PRODUCT_NAME': 'NativeQualification', 'PRODUCT_BUNDLE_IDENTIFIER': IOS_PACKAGE, 'INFOPLIST_FILE': str(sources / 'Info.plist'), 'CODE_SIGN_ENTITLEMENTS': str(entitlements), 'CODE_SIGN_IDENTITY': '-', 'SDKROOT': 'iphonesimulator', 'SUPPORTED_PLATFORMS': 'iphonesimulator', 'IPHONEOS_DEPLOYMENT_TARGET': '18.6', 'SWIFT_VERSION': '5.0', 'SWIFT_TREAT_WARNINGS_AS_ERRORS': 'YES', 'TARGETED_DEVICE_FAMILY': '1,2', 'ONLY_ACTIVE_ARCH': 'YES'}
    build_settings = ' '.join(f'{key} = {quote(value)};' for key, value in settings.items())
    objects = [
        f'{bridge} = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {quote(str(sources / "MobileKeyBridge.swift"))}; sourceTree = "<absolute>";}};',
        f'{qualification} = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {quote(str(sources / "Qualification.swift"))}; sourceTree = "<absolute>";}};',
        f'{product} = {{isa = PBXFileReference; explicitFileType = wrapper.application; path = NativeQualification.app; sourceTree = BUILT_PRODUCTS_DIR;}};',
        f'{bridge_build} = {{isa = PBXBuildFile; fileRef = {bridge};}};',
        f'{qualification_build} = {{isa = PBXBuildFile; fileRef = {qualification};}};',
        f'{group} = {{isa = PBXGroup; children = ({bridge}, {qualification}, {products},); sourceTree = "<group>";}};',
        f'{products} = {{isa = PBXGroup; children = ({product},); name = Products; sourceTree = "<group>";}};',
        f'{phase} = {{isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({bridge_build}, {qualification_build},); runOnlyForDeploymentPostprocessing = 0;}};',
        f'{config} = {{isa = XCBuildConfiguration; name = Debug; buildSettings = {{{build_settings}}};}};',
        f'{project_config} = {{isa = XCBuildConfiguration; name = Debug; buildSettings = {{}};}};',
        f'{configs} = {{isa = XCConfigurationList; buildConfigurations = ({config},); defaultConfigurationIsVisible = 0; defaultConfigurationName = Debug;}};',
        f'{project_configs} = {{isa = XCConfigurationList; buildConfigurations = ({project_config},); defaultConfigurationIsVisible = 0; defaultConfigurationName = Debug;}};',
        f'{target} = {{isa = PBXNativeTarget; buildConfigurationList = {configs}; buildPhases = ({phase},); buildRules = (); dependencies = (); name = NativeQualification; productName = NativeQualification; productReference = {product}; productType = "com.apple.product-type.application";}};',
        f'{root} = {{isa = PBXProject; buildConfigurationList = {project_configs}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; knownRegions = (en, Base,); mainGroup = {group}; productRefGroup = {products}; projectDirPath = ""; projectRoot = ""; targets = ({target},);}};',
    ]
    (project / 'project.pbxproj').write_text('// !$*UTF8*$!\n{archiveVersion = 1; classes = {}; objectVersion = 56; objects = {\n' + '\n'.join(objects) + f'\n}}; rootObject = {root};}}\n')
    return project


def ios(output, device, ownership):
    report = {'runId': str(uuid.uuid4()), 'status': 'fail', 'platform': 'ios', 'phases': [], 'cleanup': {'status': 'not_attempted'}}
    report_path = output / 'report.json'
    if report_path.is_symlink():
        raise ValueError('Qualification report cannot be a symlink')
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    installed = False
    container = None
    # File-provider Documents folders attach FinderInfo to app bundles, which
    # invalidates code signing. The SDK build stays in an owned local temporary
    # directory; project, logs and terminal evidence remain in the task output.
    build_area = tempfile.TemporaryDirectory(prefix='sunlit-mobile-qualification-')
    try:
        ios_owner(device, ownership)
        project = ios_project(output)
        # Xcode emits simulator entitlements in the supported simulator-specific
        # form. Ad hoc manual signing alone is insufficient for Keychain access.
        local_build = Path(build_area.name)
        run(['xcodebuild', '-project', project, '-target', 'NativeQualification', '-configuration', 'Debug', '-sdk', 'iphonesimulator', '-disableAutomaticPackageResolution', '-skipPackageUpdates', 'SYMROOT=' + str(local_build / 'products'), 'OBJROOT=' + str(local_build / 'objects'), 'build'])
        app = local_build / 'products/Debug-iphonesimulator/NativeQualification.app'
        ios_owner(device, ownership)
        installed = True
        run(['xcrun', 'simctl', 'install', device, app])
        container = Path(subprocess.check_output(['xcrun', 'simctl', 'get_app_container', device, IOS_PACKAGE, 'data'], text=True, timeout=30).strip())
        native_report = container / 'Library/Application Support/qualification-result.json'

        def phase(name):
            subprocess.run(['xcrun', 'simctl', 'terminate', device, IOS_PACKAGE], capture_output=True, timeout=10, shell=False)
            native_report.unlink(missing_ok=True)
            run(['xcrun', 'simctl', 'launch', device, IOS_PACKAGE, '--phase', name])
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if native_report.exists():
                    data = native_report.read_bytes()
                    if len(data) > 8192:
                        raise ValueError('Native qualification report exceeds bound')
                    value = json.loads(data)
                    if value.get('phase') != name or value.get('status') not in ('pass', 'fail', 'blocked'):
                        raise ValueError('Invalid native phase result')
                    return value
                time.sleep(1)
            raise ValueError('Native phase report timed out')

        prior = phase('cleanup'); report['priorCleanup'] = prior
        if prior['status'] != 'pass':
            report['cleanup'] = prior
            raise ValueError('Previous fixture must be cleaned before creating a key')
        for name in ('rejection_helper', 'input', 'seed', 'recover', 'tamper', 'invalidate', 'recover_deleted'):
            value = phase(name); report['phases'].append(value)
            if value['status'] == 'blocked':
                report['status'] = 'blocked'
                break
            if value['status'] != 'pass':
                raise ValueError('Native qualification assertion failed')
        else:
            report['status'] = 'pass'
        cleanup = phase('cleanup'); report['cleanup'] = cleanup
        if cleanup['status'] != 'pass':
            report['status'] = 'fail'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report['status'] = 'fail'
        report['error'] = type(error).__name__
    finally:
        if installed:
            try:
                ios_owner(device, ownership)
                # Even an assertion/build/report failure attempts key cleanup
                # before uninstall; iOS uninstall alone need not remove Keychain.
                if container is not None and report['cleanup']['status'] == 'not_attempted':
                    report['cleanup'] = phase('cleanup')
                if report['cleanup']['status'] == 'pass':
                    run(['xcrun', 'simctl', 'uninstall', device, IOS_PACKAGE])
                    report['cleanup']['appRemoved'] = True
                else:
                    # iOS uninstall need not delete Keychain. Retain the app's
                    # namespace marker so the next run can retry exact cleanup.
                    report['cleanup']['appRemoved'] = False
                    report['cleanup']['uninstallSuppressed'] = True
                    report['status'] = 'fail'
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                report['cleanup'] = {'status': 'fail', 'error': type(error).__name__}
                report['status'] = 'fail'
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        build_area.cleanup()
    print(json.dumps(report))
    return 0 if report['status'] == 'pass' else 2 if report['status'] == 'blocked' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--platform', choices=['android', 'ios'])
    parser.add_argument('--device', default='emulator-5558')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--ownership', type=Path)
    parser.add_argument('--fault-injection', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.platform is None or args.output is None:
        parser.error('--platform and --output are required')
    if args.output.is_symlink():
        raise ValueError('Qualification output cannot be a symlink')
    args.output.mkdir(parents=True, exist_ok=True)
    if args.platform == 'android':
        return android(args.output.resolve(), args.device, args.ownership, args.fault_injection)
    return ios(args.output.resolve(), args.device, args.ownership)


def self_test():
    """Host failure-path regressions; no SDK execution, emulator or key access."""
    import tempfile
    import unittest
    from unittest.mock import patch
    module = sys.modules[__name__]

    class HostFailureTests(unittest.TestCase):
        def test_ios_failed_key_cleanup_retains_app_and_namespace(self):
            with tempfile.TemporaryDirectory() as folder:
                output = Path(folder); container = output / 'generated-container'
                native = container / 'Library/Application Support'; native.mkdir(parents=True)
                marker = native / 'encrypted-fixture.json'
                commands = []; seeded = False
                def fake_run(arguments, **kwargs):
                    nonlocal seeded
                    commands.append([str(a) for a in arguments])
                    if 'launch' in arguments:
                        name = arguments[-1]
                        if name == 'seed':
                            seeded = True; marker.write_text('{"namespace":"generated-owned-fixture"}')
                        status = 'fail' if name == 'tamper' or name == 'cleanup' and seeded else 'pass'
                        (native / 'qualification-result.json').write_text(json.dumps({'phase': name, 'status': status}))
                    if 'uninstall' in arguments:
                        marker.unlink(missing_ok=True)
                with patch.object(module, 'ios_owner'), patch.object(module, 'run', side_effect=fake_run), patch.object(subprocess, 'check_output', return_value=str(container)), patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    self.assertEqual(ios(output, 'generated-device', None), 1)
                self.assertTrue(marker.exists(), 'Failed Keychain deletion must retain its namespace')
                self.assertFalse(any('uninstall' in arguments for arguments in commands))
                result = json.loads((output / 'report.json').read_text())
                self.assertEqual(result['cleanup']['status'], 'fail')

        def test_partial_native_report_waits_for_complete_json(self):
            results = [subprocess.CompletedProcess([], 0, b'', b''), subprocess.CompletedProcess([], 0, b'{"status":"pass"}', b'')]
            with patch.object(module, 'run'), patch.object(subprocess, 'run', side_effect=results), patch.object(time, 'sleep'):
                self.assertEqual(android_phase(Path('/generated/adb'), 'emulator-5558', 'seed')['status'], 'pass')

        def test_unowned_emulator_is_rejected_before_build(self):
            with tempfile.TemporaryDirectory() as folder, patch.object(module, 'run') as invoked:
                output = Path(folder)
                self.assertEqual(android(output, 'emulator-5558'), 1)
                invoked.assert_not_called()

        def test_old_pass_is_replaced_when_build_fails(self):
            with tempfile.TemporaryDirectory() as folder:
                output = Path(folder)
                (output / 'report.json').write_text('{"runId":"old","status":"pass"}')
                with patch.object(module, 'android_owner', return_value=output), patch.object(module, 'run', side_effect=subprocess.CalledProcessError(1, ['javac'])):
                    self.assertEqual(android(output, 'emulator-5558'), 1)
                result = json.loads((output / 'report.json').read_text())
                self.assertEqual(result['status'], 'fail')
                self.assertNotEqual(result['runId'], 'old')

        def test_assertion_timeout_and_cleanup_failure_have_terminal_reports(self):
            for failure, cleanup in (({'status': 'fail'}, {'status': 'pass'}), (subprocess.TimeoutExpired(['adb'], 5), {'status': 'pass'}), ({'status': 'fail'}, {'status': 'fail'})):
                with self.subTest(failure=type(failure).__name__, cleanup=cleanup['status']), tempfile.TemporaryDirectory() as folder:
                    output = Path(folder); (output / 'fixture-signing.p12').write_text('generated-host-fixture')
                    commands = []
                    def fake_run(arguments, **kwargs):
                        commands.append([str(a) for a in arguments])
                        if str(arguments[0]).endswith('/aapt2'):
                            with zipfile.ZipFile(output / 'unsigned.apk', 'w'):
                                pass
                        if str(arguments[0]).endswith('/d8'):
                            (output / 'dex/classes.dex').write_bytes(b'generated-host-fixture')
                    denied = subprocess.CompletedProcess([], 1, b'', b'not exported')
                    with patch.object(module, 'android_owner', return_value=output), patch.object(module, 'run', side_effect=fake_run), patch.object(subprocess, 'run', return_value=denied), patch.object(module, 'android_phase', side_effect=[failure, cleanup]) as phase:
                        self.assertEqual(android(output, 'emulator-5558'), 1)
                    self.assertEqual(phase.call_args_list[-1].args[-1], 'cleanup')
                    self.assertTrue(any('uninstall' in a for a in commands))
                    result = json.loads((output / 'report.json').read_text())
                    self.assertEqual(result['status'], 'fail')
                    self.assertEqual(result['cleanup']['status'], cleanup['status'])
                    self.assertTrue(result['cleanup']['appRemoved'])

    return 0 if unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(HostFailureTests)).wasSuccessful() else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Native qualification failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(2)

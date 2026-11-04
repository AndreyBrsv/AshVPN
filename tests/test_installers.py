"""Installer boundaries and release packaging, without installing software."""
import os
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tool'))
from build_installers import build_installer, build_macos_helper, build_macos_maintenance_disk


class InstallerTests(unittest.TestCase):
    def test_macos_helper_compiles_requested_arch_without_sandbox_inheritance(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            app = root / 'Helpers/Ashapp Maintenance.app'
            with patch('build_installers.subprocess.run') as run:
                build_macos_helper(root, 'macos-arm64', '0.0.8', app)
            command = run.call_args_list[0].args[0]
            self.assertIn('arm64-apple-macos12.0', command)
            self.assertEqual(command[:2], ['xcrun', 'swiftc'])
            self.assertNotIn('--entitlements', run.call_args_list[1].args[0])
            info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
            self.assertEqual(info['CFBundleIdentifier'], 'io.github.andreybrsv.ashapp.maintenance')

    def test_macos_maintenance_disk_binds_embedded_package_to_digest(self):
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'LICENSE').write_text('fixture')
            installer = root / 'fixture.pkg'
            installer.write_bytes(b'synthetic-installer')
            def fake_helper(root, target, version, app):
                (app / 'Contents/Resources').mkdir(parents=True)
                (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({}))
            def command(args, **kwargs):
                if args[0] == 'codesign' and '--force' in args:
                    app = Path(args[-1])
                    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
                    self.assertEqual(info['AshappPackageSHA256'], hashlib.sha256(installer.read_bytes()).hexdigest())
                    self.assertEqual((app / 'Contents/Resources/Installation.pkg').read_bytes(), installer.read_bytes())
                if args[0] == 'hdiutil':
                    Path(args[-1]).write_bytes(b'synthetic-disk')
            with patch('build_installers.build_macos_helper', side_effect=fake_helper), \
                    patch('build_installers.subprocess.run', side_effect=command):
                disk = build_macos_maintenance_disk(root, 'macos-x64', '0.0.8', root, installer)
            self.assertTrue(disk.is_file())

    def test_windows_packages_whole_bundle_without_force_closing_or_deleting_profiles(self):
        source = (ROOT / 'tool/windows_setup.iss').read_text()
        self.assertIn('PrivilegesRequired=lowest', source)
        self.assertIn('AppMutex=Ashapp.Desktop.Running', source)
        self.assertIn('CloseApplications=no', source)
        self.assertIn('recursesubdirs createallsubdirs', source)
        self.assertNotIn('[InstallDelete]', source)
        self.assertNotIn('[UninstallDelete]', source)
        self.assertNotIn('servers.json', source)

    def test_macos_replaces_only_application_bundle_without_install_scripts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            app = root / 'flutter/build/macos/Build/Products/Release/Ashapp.app'
            app.mkdir(parents=True)
            (app / 'synthetic-app').write_text('fixture')
            output = root / 'output'
            output.mkdir()

            def package(command, **kwargs):
                self.assertEqual(command[0], 'pkgbuild')
                self.assertNotIn('--scripts', command)
                self.assertEqual(command[command.index('--install-location') + 1], '/Applications')
                components = plistlib.loads(Path(command[command.index('--component-plist') + 1]).read_bytes())
                self.assertEqual(components[0]['RootRelativeBundlePath'], 'Ashapp.app')
                self.assertFalse(components[0]['BundleIsRelocatable'])
                self.assertTrue(components[0]['BundleIsVersionChecked'])
                self.assertTrue(components[0]['BundleHasStrictIdentifier'])
                Path(command[-1]).write_bytes(b'synthetic-installer')
            with patch('build_installers.subprocess.run', side_effect=package):
                result = build_installer(root, 'macos-arm64', '0.0.4', output)
            self.assertEqual(result.name, 'Ashapp-v0.0.4-macos-arm64-setup.pkg')

    def test_windows_compiler_receives_separate_arguments_for_paths_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='ashapp installer ') as folder:
            root = Path(folder)
            compiler = root / 'ISCC.exe'
            compiler.write_bytes(b'synthetic-compiler')
            output = root / 'output'
            output.mkdir()
            with patch.dict(os.environ, {'INNO_ISCC': str(compiler)}):
                def compile_setup(command, **kwargs):
                    self.assertEqual(command[0], str(compiler))
                    self.assertIn(f'/DSourceRoot={root}', command)
                    self.assertNotIn('shell', kwargs)
                    (output / 'Ashapp-v0.0.4-windows-x64-setup.exe').write_bytes(b'synthetic-installer')
                with patch('build_installers.subprocess.run', side_effect=compile_setup):
                    build_installer(root, 'windows-x64', '0.0.4', output)

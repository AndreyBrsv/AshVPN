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
from build_installers import build_installer


class InstallerTests(unittest.TestCase):
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

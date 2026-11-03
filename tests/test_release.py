"""Verify release identity gates without native builds or network access."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1] / 'tool'
sys.path.insert(0, str(TOOL))
import prepare_release
from package_release import VERSION, sha256


class ReleaseIdentityTests(unittest.TestCase):
    def create_assets(self, directory, commit):
        for target in ('windows-x64', 'macos-x64', 'macos-arm64'):
            stem = f'Ashapp-v{VERSION}-{target}'
            archive = directory / f'{stem}.zip'
            archive.write_bytes(b'synthetic-archive-placeholder')
            suffix = '.exe' if target == 'windows-x64' else '.pkg'
            installer = directory / f'{stem}-setup{suffix}'
            installer.write_bytes(b'synthetic-non-executable-installer')
            (directory / f'{stem}.build.json').write_text(json.dumps({
                'version': VERSION, 'target': target, 'source_commit': commit,
                'archive': archive.name, 'sha256': sha256(archive),
                'installer': installer.name, 'installer_sha256': sha256(installer),
                'installer_size': installer.stat().st_size}))

    def test_tampered_installer_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            self.create_assets(directory, 'same-commit-placeholder')
            (directory / f'Ashapp-v{VERSION}-windows-x64-setup.exe').write_bytes(b'changed')
            with patch.object(prepare_release.subprocess, 'check_output', return_value='same-commit-placeholder'), \
                    patch.object(prepare_release.subprocess, 'run') as archive:
                with self.assertRaisesRegex(ValueError, 'Installer'):
                    prepare_release.prepare(directory)
                archive.assert_not_called()

    def test_checksums_include_all_installers_and_matching_source(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            self.create_assets(directory, 'same-commit-placeholder')
            def source_archive(*args, **kwargs):
                (directory / f'Ashapp-v{VERSION}-source.zip').write_bytes(b'synthetic-source')
            with patch.object(prepare_release.subprocess, 'check_output', return_value='same-commit-placeholder'), \
                    patch.object(prepare_release.subprocess, 'run', side_effect=source_archive):
                prepare_release.prepare(directory)
            sums = (directory / 'SHA256SUMS').read_text()
            self.assertEqual(sums.count('-setup.exe'), 1)
            self.assertEqual(sums.count('-setup.pkg'), 2)
            self.assertIn(f'Ashapp-v{VERSION}-source.zip', sums)

    def test_mixed_source_commits_are_rejected_before_creating_source_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            self.create_assets(directory, 'old-commit-placeholder')
            with patch.object(prepare_release.subprocess, 'check_output', return_value='new-commit-placeholder'), \
                    patch.object(prepare_release.subprocess, 'run') as archive:
                with self.assertRaisesRegex(ValueError, 'mismatch'):
                    prepare_release.prepare(directory)
                archive.assert_not_called()

    def test_tampered_binary_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            self.create_assets(directory, 'same-commit-placeholder')
            (directory / f'Ashapp-v{VERSION}-macos-arm64.zip').write_bytes(b'changed')
            with patch.object(prepare_release.subprocess, 'check_output', return_value='same-commit-placeholder'), \
                    patch.object(prepare_release.subprocess, 'run') as archive:
                with self.assertRaisesRegex(ValueError, 'mismatch'):
                    prepare_release.prepare(directory)
                archive.assert_not_called()

    def test_missing_native_platform_prevents_partial_release(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            self.create_assets(directory, 'same-commit-placeholder')
            (directory / f'Ashapp-v{VERSION}-macos-x64.build.json').unlink()
            with patch.object(prepare_release.subprocess, 'check_output', return_value='same-commit-placeholder'), \
                    patch.object(prepare_release.subprocess, 'run') as archive:
                with self.assertRaises(FileNotFoundError):
                    prepare_release.prepare(directory)
                archive.assert_not_called()

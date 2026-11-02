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
            (directory / f'{stem}.build.json').write_text(json.dumps({
                'version': VERSION, 'target': target, 'source_commit': commit,
                'archive': archive.name, 'sha256': sha256(archive)}))

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

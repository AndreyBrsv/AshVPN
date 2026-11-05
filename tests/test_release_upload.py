"""Safe retry behavior for immutable GitHub release files."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tool'))
import upload_release_assets


class ReleaseUploadTests(unittest.TestCase):
    def test_identical_asset_is_not_uploaded_again(self):
        with tempfile.TemporaryDirectory() as temp:
            asset = Path(temp) / 'asset.zip'
            asset.write_bytes(b'example')
            digest = 'sha256:' + hashlib.sha256(b'example').hexdigest()
            response = json.dumps({'assets': [{'name': asset.name, 'digest': digest}]})
            with patch.object(upload_release_assets.subprocess, 'check_output', return_value=response), \
                    patch.object(upload_release_assets.subprocess, 'run') as run:
                upload_release_assets.upload('v1', [asset])
                run.assert_not_called()

    def test_different_or_unknown_digest_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            asset = Path(temp) / 'asset.zip'
            asset.write_bytes(b'example')
            for digest in (None, 'sha256:wrong'):
                response = json.dumps({'assets': [{'name': asset.name, 'digest': digest}]})
                with self.subTest(digest=digest), \
                        patch.object(upload_release_assets.subprocess, 'check_output', return_value=response), \
                        patch.object(upload_release_assets.subprocess, 'run') as run:
                    with self.assertRaises(ValueError):
                        upload_release_assets.upload('v1', [asset])
                    run.assert_not_called()

    def test_missing_asset_is_uploaded(self):
        with tempfile.TemporaryDirectory() as temp:
            asset = Path(temp) / 'asset.zip'
            asset.write_bytes(b'example')
            with patch.object(upload_release_assets.subprocess, 'check_output', return_value='{"assets": []}'), \
                    patch.object(upload_release_assets.subprocess, 'run') as run:
                upload_release_assets.upload('v1', [asset])
                run.assert_called_once_with(['gh', 'release', 'upload', 'v1', str(asset)], check=True)

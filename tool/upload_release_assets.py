"""Upload immutable release assets, allowing safe retries of identical files."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def upload(tag, paths):
    for path in paths:
        path = Path(path)
        assets = json.loads(subprocess.check_output(
            ['gh', 'api', 'repos/{owner}/{repo}/releases/tags/' + tag], text=True))['assets']
        existing = [asset for asset in assets if asset['name'] == path.name]
        if existing:
            digest = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
            if len(existing) != 1 or existing[0].get('digest') != digest:
                raise ValueError(f'Published asset differs or has no digest: {path.name}; refusing to overwrite.')
            print(f'Already published and verified: {path.name}')
        else:
            subprocess.run(['gh', 'release', 'upload', tag, str(path)], check=True)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit('Usage: upload_release_assets.py TAG FILE [FILE ...]')
    upload(sys.argv[1], sys.argv[2:])

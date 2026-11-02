"""Assemble checksums only after all native assets match this source commit."""
import argparse
import json
import subprocess
from pathlib import Path

from package_release import ROOT, VERSION, sha256


def prepare(output):
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    expected = ('windows-x64', 'macos-x64', 'macos-arm64')
    for target in expected:
        stem = f'Ashapp-v{VERSION}-{target}'
        manifest = json.loads((output / f'{stem}.build.json').read_text(encoding='utf-8'))
        if (manifest['source_commit'] != revision or manifest['version'] != VERSION
                or manifest['target'] != target or manifest['archive'] != f'{stem}.zip'
                or manifest['sha256'] != sha256(output / f'{stem}.zip')):
            raise ValueError('Build identity or archive checksum mismatch.')
    source = output / f'Ashapp-v{VERSION}-source.zip'
    subprocess.run(['git', 'archive', '--format=zip', f'--prefix=Ashapp-{VERSION}/',
                    f'--output={source}', revision], cwd=ROOT, check=True)
    artifacts = sorted(output.glob('Ashapp-*.zip')) + sorted(output.glob('Ashapp-*.build.json'))
    (output / 'SHA256SUMS').write_text(''.join(f'{sha256(p)}  {p.name}\n' for p in artifacts), encoding='utf-8')
    print(f'Release v{VERSION} verified against {revision}.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    prepare(parser.parse_args().output.resolve())

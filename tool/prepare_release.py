"""Assemble checksums only after all native assets match this source commit."""
import argparse
import json
import subprocess
from pathlib import Path

from package_release import ROOT, VERSION, sha256


def prepare(output, target=None):
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    selected_target = target
    targets = ('windows-x64', 'macos-x64', 'macos-arm64')
    if target is not None and target not in targets:
        raise ValueError('Unsupported target.')
    expected = (target,) if target else targets
    artifacts = []
    for target in expected:
        stem = f'Ashapp-v{VERSION}-{target}'
        manifest = json.loads((output / f'{stem}.build.json').read_text(encoding='utf-8'))
        if (manifest['source_commit'] != revision or manifest['version'] != VERSION
                or manifest['target'] != target or manifest['archive'] != f'{stem}.zip'
                or manifest['sha256'] != sha256(output / f'{stem}.zip')):
            raise ValueError('Build identity or archive checksum mismatch.')
        suffix = '.exe' if target == 'windows-x64' else '.pkg'
        installer = output / f'{stem}-setup{suffix}'
        if (manifest.get('installer') != installer.name or not installer.is_file()
                or manifest.get('installer_sha256') != sha256(installer)
                or manifest.get('installer_size') != installer.stat().st_size):
            raise ValueError('Installer identity or checksum mismatch.')
        artifacts.extend([output / f'{stem}.zip', output / f'{stem}.build.json', installer])
        if target.startswith('macos-'):
            maintenance = output / f'{stem}-maintenance.dmg'
            if (manifest.get('maintenance') != maintenance.name or not maintenance.is_file()
                    or manifest.get('maintenance_sha256') != sha256(maintenance)
                    or manifest.get('maintenance_size') != maintenance.stat().st_size):
                raise ValueError('Maintenance identity or checksum mismatch.')
            artifacts.append(maintenance)
    if selected_target:
        allowed = {item.name for item in artifacts}
        sums = output / f'Ashapp-v{VERSION}-{selected_target}-SHA256SUMS'
        if any(item.name not in allowed | {sums.name} for item in output.iterdir()):
            raise ValueError('Unexpected files in release output.')
        sums.write_text(''.join(f'{sha256(p)}  {p.name}\n' for p in artifacts), encoding='utf-8')
        print(f'{selected_target} v{VERSION} verified against {revision}.')
        return
    source = output / f'Ashapp-v{VERSION}-source.zip'
    subprocess.run(['git', 'archive', '--format=zip', f'--prefix=Ashapp-{VERSION}/',
                    f'--output={source}', revision], cwd=ROOT, check=True)
    artifacts.append(source)
    allowed = {item.name for item in artifacts}
    if any(item.name not in allowed | {'SHA256SUMS'} for item in output.iterdir()):
        raise ValueError('Unexpected files in release output.')
    (output / 'SHA256SUMS').write_text(''.join(f'{sha256(p)}  {p.name}\n' for p in artifacts), encoding='utf-8')
    print(f'Release v{VERSION} verified against {revision}.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', choices=('windows-x64', 'macos-x64', 'macos-arm64'))
    args = parser.parse_args()
    prepare(args.output.resolve(), args.target)

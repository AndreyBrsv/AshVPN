"""Install/repair/uninstall only in an isolated disposable Windows CI profile.

Never run Ashapp or request credential cleanup. Refuse local developer runs.
"""
import os
import subprocess
import tempfile
import time
from pathlib import Path

from package_release import ROOT, VERSION


def smoke():
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Installer smoke test is restricted to disposable Windows CI.')
    installer = ROOT / f'release-output/Ashapp-v{VERSION}-windows-x64-setup.exe'
    if not installer.is_file():
        raise RuntimeError('Packaged installer is missing.')
    with tempfile.TemporaryDirectory(prefix='ashapp-installer-smoke-') as temporary:
        folder = Path(temporary)
        destination = folder / 'application'
        for operation in ('install', 'repair'):
            log = folder / f'{operation}.log'
            result = subprocess.run([str(installer), '/VERYSILENT', '/SP-', '/NORESTART',
                                     f'/DIR={destination}', f'/LOG={log}'], timeout=120)
            if result.returncode != 0:
                raise RuntimeError(f'Installer {operation} failed: {result.returncode}')
            if not (destination / 'ashapp.exe').is_file() or not (destination / 'unins000.exe').is_file():
                raise RuntimeError(f'Installer {operation} did not produce the complete application.')
        subprocess.run([str(destination / 'unins000.exe'), '/VERYSILENT', '/NORESTART'],
                       check=True, timeout=120)
        deadline = time.monotonic() + 15
        while destination.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        if (destination / 'ashapp.exe').exists():
            raise RuntimeError('Uninstall did not remove the isolated executable.')
    print('Disposable Windows install, repair and uninstall passed; no app/vault access.')


if __name__ == '__main__':
    smoke()

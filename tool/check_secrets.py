"""Scan publishable source with a checksum-pinned Gitleaks executable."""
import hashlib
import io
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = '8.30.1'
CHECKSUMS = {
    'windows_x64.zip': 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e',
    'darwin_x64.tar.gz': 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709',
    'darwin_arm64.tar.gz': 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5',
    'linux_x64.tar.gz': '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
}


def scan():
    system = {'Windows': 'windows', 'Darwin': 'darwin', 'Linux': 'linux'}[platform.system()]
    arch = 'arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x64'
    suffix = f'{system}_{arch}' + ('.zip' if system == 'windows' else '.tar.gz')
    name = f'gitleaks_{VERSION}_{suffix}'
    with urllib.request.urlopen(f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/{name}', timeout=60) as response:
        data = response.read(30 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != CHECKSUMS[suffix]:
        raise ValueError('Secret scanner checksum mismatch.')
    with tempfile.TemporaryDirectory(prefix='ashapp-secret-scan-') as folder:
        directory = Path(folder)
        executable = directory / ('gitleaks.exe' if system == 'windows' else 'gitleaks')
        if system == 'windows':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                executable.write_bytes(archive.read(executable.name))
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                executable.write_bytes(archive.extractfile('gitleaks').read())
            executable.chmod(0o700)
        source = directory / 'source'
        source.mkdir()
        files = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().split('\0')
        for relative in filter(None, files):
            item = ROOT / relative
            if item.is_symlink():
                raise ValueError('Review source symlinks before secret scanning.')
            if not item.is_file():
                continue
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)
        subprocess.run([str(executable), 'dir', str(source), '--redact', '--no-banner'], check=True)
        subprocess.run([str(executable), 'git', str(ROOT), '--redact', '--no-banner', '--log-opts=--all'], check=True)


if __name__ == '__main__':
    scan()

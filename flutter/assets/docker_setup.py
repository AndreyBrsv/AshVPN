#!/usr/bin/env python3
"""Install a fresh Docker daemon using Docker's scoped, authenticated APT repo.

Never replaces an existing runtime, removes conflicting packages, changes daemon
configuration, or restarts another application's containers.
"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request

FINGERPRINT = '9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
SOURCE = Path('etc/apt/sources.list.d/ashapp-docker.sources')
KEYRING = Path('usr/share/keyrings/ashapp-docker.gpg')
SUPPORTED = {('debian', '12'): 'bookworm', ('ubuntu', '22.04'): 'jammy',
             ('ubuntu', '24.04'): 'noble'}
CONFLICTS = ('docker.io', 'docker-ce', 'docker-ce-cli', 'docker-compose',
             'docker-compose-v2', 'docker-doc', 'docker-buildx', 'podman-docker',
             'containerd', 'containerd.io', 'runc')


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def safe_path(path, directory=False):
    for parent in (*reversed(path.parents), path):
        if parent.is_symlink():
            raise ValueError('Linked Docker package setup paths require manual review.')
        if parent.exists():
            value = parent.stat()
            if value.st_uid != 0 or value.st_mode & 0o022:
                raise ValueError('Docker package setup paths must be root-owned and protected.')
            if parent != path or directory:
                if not stat.S_ISDIR(value.st_mode):
                    raise ValueError('Docker package setup parent is not a directory.')
            elif not stat.S_ISREG(value.st_mode):
                raise ValueError('Docker package setup target is not a regular file.')


def atomic(path, payload):
    safe_path(path)
    missing, parent = [], path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
    fd, name = tempfile.mkstemp(prefix='.ashapp-docker-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def environment(root, command):
    text = (root / 'etc/os-release').read_text()
    values = {}
    for line in text.splitlines():
        if re.match(r'^[A-Z_]+=', line):
            name, value = line.split('=', 1)
            values[name] = value.strip('"\'')
    identity = values.get('ID'), values.get('VERSION_ID')
    if identity not in SUPPORTED:
        raise ValueError('Docker setup supports Debian 12 and Ubuntu 22.04/24.04.')
    architecture = command(['dpkg', '--print-architecture'], capture_output=True).stdout.strip()
    if architecture not in ('amd64', 'arm64'):
        raise ValueError('Docker setup supports amd64 and arm64 Linux servers.')
    return identity[0], SUPPORTED[identity], architecture


def source_text(distro, codename, architecture):
    return (f'Types: deb\nURIs: https://download.docker.com/linux/{distro}\n'
            f'Suites: {codename}\nComponents: stable\nArchitectures: {architecture}\n'
            'Signed-By: /usr/share/keyrings/ashapp-docker.gpg\n')


def check_sources(root, expected):
    source = root / SOURCE
    candidates = [root / 'etc/apt/sources.list',
                  *(root / 'etc/apt/sources.list.d').glob('*.list'),
                  *(root / 'etc/apt/sources.list.d').glob('*.sources')]
    for path in candidates:
        if not path.exists() and not path.is_symlink():
            continue
        safe_path(path)
        text = path.read_text()
        if path == source and text == expected:
            continue
        if path == source or any('download.docker.com' in line.split('#', 1)[0]
                                 for line in text.splitlines()):
            raise ValueError('An existing Docker APT source requires manual review; nothing was replaced.')
    safe_path(root / KEYRING)
    if (root / KEYRING).exists() and (not source.exists() or source.read_text() != expected):
        raise ValueError('The dedicated Docker keyring is occupied without its matching source. Review it before setup.')


def prepare_repository(root, distro, codename, architecture, command, fetch):
    text = source_text(distro, codename, architecture)
    check_sources(root, text)
    # Use the existing primary-fingerprint parser shared with the reviewed PPA
    # bootstrap; a signing subkey alone cannot satisfy the pinned identity.
    spec = importlib.util.spec_from_file_location('ashapp_apt_key', Path(__file__).with_name('awg_setup.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='ashapp-docker-key-') as folder:
        temporary = Path(folder)
        armored, binary = temporary / 'key.asc', temporary / 'key.gpg'
        with fetch(f'https://download.docker.com/linux/{distro}/gpg', timeout=30) as response:
            payload = response.read(1024 * 1024 + 1)
        if not payload or len(payload) > 1024 * 1024:
            raise ValueError('The Docker package signing key has an invalid size.')
        armored.write_bytes(payload)
        base = ['gpg', '--no-options', '--batch', '--homedir', folder]
        metadata = command([*base, '--with-colons', '--show-keys', str(armored)],
                           capture_output=True, timeout=30)
        if module.primary_fingerprints(metadata.stdout) != [FINGERPRINT]:
            raise ValueError('Docker signing key fingerprint mismatch; APT trust was not changed.')
        command([*base, '--dearmor', '--output', str(binary), str(armored)],
                capture_output=True, timeout=30)
        if (root / KEYRING).exists() and (root / KEYRING).read_bytes() != binary.read_bytes():
            raise ValueError('The dedicated Docker keyring changed. APT trust was not overwritten.')
        atomic(root / KEYRING, binary.read_bytes())
        atomic(root / SOURCE, text.encode())


def select_version(text):
    # Docker's stable APT feed contains historic releases. Use an explicit
    # version from its authenticated package index; our bridge-policy verifier
    # covers the normal Engine 28/29 rule shapes, not future daemon changes.
    for line in text.splitlines():
        fields = line.split('|')
        if len(fields) < 2:
            continue
        version = fields[1].strip()
        if (re.fullmatch(r'(?:[0-9]+:)?(?:28|29)\.[0-9]+\.[0-9]+-[A-Za-z0-9.+~_-]+', version)
                and not re.search(r'alpha|beta|rc|dev|nightly|test', version, re.I)):
            return version
    raise ValueError('No supported stable Docker Engine 28/29 package is available in the verified repository.')


def ensure(root=Path('/'), command=run, fetch=urllib.request.urlopen, which=shutil.which):
    if which('docker'):
        try:
            command(['docker', 'info'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise ValueError('The existing Docker daemon is unavailable. Start or repair it manually; Ashapp does not restart a shared daemon.') from None
        return False
    distro, codename, architecture = environment(root, command)
    expected = source_text(distro, codename, architecture)
    check_sources(root, expected)
    # Absence of the CLI does not establish a fresh host: refuse runtime data
    # and packages that a different container manager may still own.
    for folder in ('var/lib/docker', 'var/lib/containerd'):
        path = root / folder
        if path.is_symlink() or (path.exists() and (not path.is_dir() or any(path.iterdir()))):
            raise ValueError('Existing container runtime data requires manual review before Docker installation.')
    installed = command(['dpkg-query', '-W', '-f=${binary:Package}\t${db:Status-Status}\n'],
                        capture_output=True).stdout
    for line in installed.splitlines():
        name, _, state = line.partition('\t')
        if name.split(':', 1)[0] in CONFLICTS and state == 'installed':
            raise ValueError('An existing container runtime package requires manual review; Ashapp will not remove or upgrade it.')
    apt = ['apt-get', '-o', 'DPkg::Options::=--force-confold', '-o', 'DPkg::Lock::Timeout=180']
    print('[INFO] Installing a fresh Docker daemon from its verified official APT repository.', flush=True)
    command([*apt, 'update'])
    command([*apt, 'install', '-y', 'ca-certificates', 'gnupg'])
    prepare_repository(root, distro, codename, architecture, command, fetch)
    command([*apt, 'update'])
    available = command(['apt-cache', 'madison', 'docker-ce'], capture_output=True).stdout
    version = select_version(available)
    command([*apt, 'install', '-y', '--no-install-recommends', 'docker-ce=' + version,
             'docker-ce-cli=' + version, 'containerd.io', 'docker-buildx-plugin'])
    command(['systemctl', 'enable', '--now', 'docker'])
    command(['docker', 'info'], stdout=subprocess.DEVNULL)
    return True


if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise ValueError('Docker setup requires root.')
        os.umask(0o077)
        ensure()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, ValueError) else 'Docker package setup failed. Check APT and daemon status; no existing daemon was intentionally replaced.'
        print('ERROR: ' + message, file=sys.stderr)
        sys.exit(1)

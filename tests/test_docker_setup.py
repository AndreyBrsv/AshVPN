"""Fresh Docker bootstrap uses fake package commands and isolated files only."""
from contextlib import nullcontext
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('docker_setup_test', ROOT / 'server/docker_setup.py')
docker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docker)


class DockerSetupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        (self.root / 'etc').mkdir()
        (self.root / 'etc/os-release').write_text('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
        self.calls = []
        self.installed = ''
        self.fingerprint = docker.FINGERPRINT
        self.fetch = Mock()
        self.fetch.return_value.__enter__ = Mock(return_value=SimpleNamespace(read=lambda _: b'synthetic-public-key'))
        self.fetch.return_value.__exit__ = Mock(return_value=None)
        # Production ownership checks remain active. Windows fixtures cannot
        # represent protected uid/mode metadata; native coverage is separate.
        owner = patch.object(docker, 'safe_path')
        owner.start(); self.addCleanup(owner.stop)
        if not hasattr(os, 'fchmod'):
            mode = patch.object(docker.os, 'fchmod', create=True)
            mode.start(); self.addCleanup(mode.stop)

    def command(self, args, **kwargs):
        self.calls.append(args)
        text = ''
        if args == ['dpkg', '--print-architecture']:
            text = 'amd64\n'
        elif args[0] == 'dpkg-query':
            text = self.installed
        elif args[:2] == ['apt-cache', 'madison']:
            text = 'docker-ce | 5:30.0.0-1~debian.12~bookworm | stable\ndocker-ce | 5:29.1.3-1~debian.12~bookworm | stable\n'
        elif args[0] == 'gpg':
            if '--show-keys' in args:
                text = 'pub::::::::::\nfpr:::::::::' + self.fingerprint + ':\n'
            if '--dearmor' in args:
                Path(args[args.index('--output') + 1]).write_bytes(b'synthetic-keyring')
        return SimpleNamespace(stdout=text)

    def test_existing_daemon_is_only_inspected_not_restarted_upgraded_or_enabled(self):
        self.assertFalse(docker.ensure(self.root, self.command, self.fetch, which=lambda _: '/usr/bin/docker'))
        self.assertEqual(self.calls, [['docker', 'info']])
        self.fetch.assert_not_called()
        self.assertFalse((self.root / docker.SOURCE).exists())

    def test_unavailable_existing_daemon_is_not_automatically_started(self):
        command = Mock(side_effect=subprocess.CalledProcessError(1, ['docker', 'info']))
        with self.assertRaisesRegex(ValueError, 'existing Docker daemon is unavailable'):
            docker.ensure(self.root, command, self.fetch, which=lambda _: '/usr/bin/docker')
        command.assert_called_once()
        self.fetch.assert_not_called()

    def test_fresh_debian_uses_bookworm_official_scoped_repo_and_supported_exact_version(self):
        self.assertTrue(docker.ensure(self.root, self.command, self.fetch, which=lambda _: None))
        source = (self.root / docker.SOURCE).read_text()
        self.assertIn('URIs: https://download.docker.com/linux/debian\n', source)
        self.assertIn('Suites: bookworm\n', source)
        self.assertIn('Signed-By: /usr/share/keyrings/ashapp-docker.gpg\n', source)
        install = next(args for args in self.calls if any(value.startswith('docker-ce=') for value in args))
        self.assertIn('docker-ce=5:29.1.3-1~debian.12~bookworm', install)
        self.assertIn('docker-ce-cli=5:29.1.3-1~debian.12~bookworm', install)
        self.assertNotIn('docker.io', install)
        self.assertEqual(self.calls[-2:], [['systemctl', 'enable', '--now', 'docker'], ['docker', 'info']])
        self.assertFalse(any(args[0] in ('sh', 'bash', 'curl') for args in self.calls))

    def test_existing_runtime_package_or_data_prevents_all_package_mutations(self):
        self.installed = 'containerd\tinstalled\n'
        with self.assertRaisesRegex(ValueError, 'runtime package'):
            docker.ensure(self.root, self.command, self.fetch, which=lambda _: None)
        self.assertFalse(any(args[0] == 'apt-get' for args in self.calls))
        self.installed = ''
        path = self.root / 'var/lib/docker'
        path.mkdir(parents=True)
        (path / 'preserved').write_text('unrelated')
        with self.assertRaisesRegex(ValueError, 'runtime data'):
            docker.ensure(self.root, self.command, self.fetch, which=lambda _: None)
        self.assertEqual((path / 'preserved').read_text(), 'unrelated')
        self.fetch.assert_not_called()

    def test_foreign_source_is_not_overwritten(self):
        path = self.root / 'etc/apt/sources.list.d/docker.list'
        path.parent.mkdir(parents=True)
        path.write_text('deb https://download.docker.com/linux/debian bookworm stable\n')
        with self.assertRaisesRegex(ValueError, 'APT source requires manual review'):
            docker.ensure(self.root, self.command, self.fetch, which=lambda _: None)
        self.assertFalse(any(args[0] == 'apt-get' for args in self.calls))
        self.fetch.assert_not_called()

    def test_wrong_primary_key_never_creates_apt_trust(self):
        self.fingerprint = 'A' * 40
        with self.assertRaisesRegex(ValueError, 'fingerprint mismatch'):
            docker.prepare_repository(self.root, 'debian', 'bookworm', 'amd64', self.command, self.fetch)
        self.assertFalse((self.root / docker.KEYRING).exists())
        self.assertFalse((self.root / docker.SOURCE).exists())

    def test_supported_os_detection_does_not_reuse_ubuntu_repo_on_debian(self):
        for distro, version, expected in [('debian', '12', 'bookworm'), ('ubuntu', '22.04', 'jammy'), ('ubuntu', '24.04', 'noble')]:
            (self.root / 'etc/os-release').write_text(f'ID={distro}\nVERSION_ID="{version}"\n')
            self.assertEqual(docker.environment(self.root, self.command), (distro, expected, 'amd64'))
        (self.root / 'etc/os-release').write_text('ID=debian\nVERSION_ID="13"\n')
        with self.assertRaisesRegex(ValueError, 'supports Debian 12'):
            docker.environment(self.root, self.command)

    def test_stable_version_selection_rejects_old_pre_release_and_unknown_major(self):
        for version in ('5:20.10.0-1~debian.12', '5:29.1.0-rc1~debian.12', '5:30.0.0-1~debian.12'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                docker.select_version('docker-ce | ' + version + ' | stable')


if __name__ == '__main__':
    unittest.main()

"""Validate the configured adapter without installing packages or touching a VPS."""
import importlib.util
import re
import subprocess
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('awg_setup', ROOT / 'server' / 'awg_setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class ConfiguredSetupTests(unittest.TestCase):
    def test_active_package_script_has_scoped_bootstrap_and_keeps_vendor_pin(self):
        original = (ROOT / 'vendor/amneziawg-install.sh').read_bytes()
        script = setup.package_script(original)
        self.assertNotIn('apt-key', script)
        self.assertNotIn('--recv-keys', script)
        self.assertIn('--prepare-ppa', script)
        self.assertIn('apt install -y gnupg', script)

    def test_primary_fingerprint_parser_rejects_short_subkey_and_extra_primary(self):
        def fingerprint(value):
            return 'fpr:::::::::' + value + ':\n'
        valid = 'pub::::::::::\n' + fingerprint(setup.PPA_FINGERPRINT)
        self.assertEqual(setup.primary_fingerprints(valid + 'sub::::::::::\n' + fingerprint('A' * 40)),
                         [setup.PPA_FINGERPRINT])
        for metadata in ('pub::::::::::\n' + fingerprint('57290828'), 'pub::::::::::\nsub::::::::::\n',
                         'sec::::::::::\n' + fingerprint(setup.PPA_FINGERPRINT)):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                setup.primary_fingerprints(metadata)

    def test_wrong_signing_key_never_changes_apt_trust(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response = MagicMock()
            response.__enter__.return_value.read.return_value = b'public-key-fixture'
            command = Mock(return_value=SimpleNamespace(stdout='pub::::::::::\nfpr:::::::::' + 'A' * 40 + ':\n'))
            with self.assertRaisesRegex(ValueError, 'fingerprint mismatch'):
                setup.prepare_ppa(root, fetch=Mock(return_value=response), command=command)
            self.assertFalse(list(root.rglob('*')))
            self.assertEqual(command.call_count, 1)

    def test_public_key_and_both_sources_use_dedicated_keyring(self):
        from contextlib import nullcontext
        import os
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response = MagicMock()
            response.__enter__.return_value.read.return_value = b'public-key-fixture'
            def command(args, **kwargs):
                if '--dearmor' in args:
                    Path(args[args.index('--output') + 1]).write_bytes(b'public-keyring-fixture')
                return SimpleNamespace(stdout='pub::::::::::\nfpr:::::::::' + setup.PPA_FINGERPRINT + ':\n')
            # Windows has no POSIX fchmod; this case verifies routing/metadata.
            mode = nullcontext() if hasattr(os, 'fchmod') else patch.object(setup.os, 'fchmod', create=True)
            with mode:
                setup.prepare_ppa(root, fetch=Mock(return_value=response), command=command)
            self.assertEqual((root / 'usr/share/keyrings/ashapp-amnezia.gpg').read_bytes(), b'public-keyring-fixture')
            text = (root / 'etc/apt/sources.list.d/ashapp-amnezia.list').read_text()
            self.assertEqual(text.count('[signed-by=/usr/share/keyrings/ashapp-amnezia.gpg]'), 2)
            self.assertIn('deb-src ', text)
            # A second, unscoped legacy source must be reviewed before any fetch.
            (root / 'etc/apt/sources.list.d/legacy.list').write_text('deb ' + setup.PPA_URL + ' focal main\n')
            fetch = Mock()
            with self.assertRaisesRegex(ValueError, 'existing Amnezia'):
                setup.prepare_ppa(root, fetch=fetch, command=command)
            fetch.assert_not_called()

    def test_existing_container_stops_setup_before_package_or_config_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            backend = SimpleNamespace(
                AWG_DIR=Path(folder), read_fields=lambda: ['203.0.113.10', '585', '1.1.1.1'],
                amnezia_containers=Mock(return_value=[{'source': 'amnezia-awg'}]), run=Mock())
            fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _: None))
            with patch.object(setup.os, 'geteuid', return_value=0, create=True), \
                    patch.object(setup.importlib.util, 'spec_from_file_location', return_value=fake_spec), \
                    patch.object(setup.importlib.util, 'module_from_spec', return_value=backend):
                with self.assertRaisesRegex(ValueError, 'will not be replaced'):
                    setup.main()
            backend.run.assert_not_called()
            self.assertFalse(list(Path(folder).iterdir()))

    def test_failed_service_activation_removes_partial_config_and_restores_forwarding(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            forwarding = directory / 'forwarding'
            forwarding.write_bytes(b'original setting\n')
            calls = []

            def run(args, check=True):
                calls.append(args)
                if args[:3] == ['systemctl', 'enable', '--now']:
                    raise RuntimeError('injected activation failure')
                return SimpleNamespace(stdout='0\n')

            def write(path, text, mode=0o600):
                path.write_text(text)

            backend = SimpleNamespace(run=run, atomic_write=write, verified_kernel=Mock(return_value=True))
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                setup.activate_configuration(backend, directory, 'params', 'config', forwarding)
            self.assertFalse((directory / 'params').exists())
            self.assertFalse((directory / 'awg0.conf').exists())
            self.assertEqual(forwarding.read_text(), 'original setting\n')
            self.assertIn(['sysctl', '-w', 'net.ipv4.ip_forward=0'], calls)
            # A clean retry can now activate without a stale "already configured" marker.
            backend.run = Mock(return_value=SimpleNamespace(stdout='0\n'))
            setup.activate_configuration(backend, directory, 'params', 'config', forwarding)
            self.assertEqual((directory / 'awg0.conf').read_text(), 'config')

    def test_package_routine_has_no_question_or_client_calls(self):
        original = (ROOT / 'vendor' / 'amneziawg-install.sh').read_bytes()
        script = setup.package_script(original)
        # Inspect the last definition, which overrides the interactive function.
        invoked = script.rsplit('function installAmneziaWG() {', 1)[1]
        self.assertNotIn('installQuestions', invoked)
        self.assertNotIn('newClient', invoked)
        self.assertIn('apt install -y amneziawg amneziawg-tools', invoked)
        self.assertTrue(script.endswith('initialCheck\ninstallAmneziaWG\n'))
        bash = Path('C:/Program Files/Git/bin/bash.exe')
        if bash.exists():
            result = subprocess.run([str(bash), '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_modified_vendor_is_rejected_before_any_execution(self):
        with self.assertRaisesRegex(ValueError, 'checksum'):
            setup.package_script(b'echo unexpected')

    def test_ipv4_kernel_configuration_contains_requested_port_dns_and_safe_nat(self):
        params, config = setup.configure('203.0.113.10', 585, '9.9.9.9', 'ens3',
                                         'private-test-placeholder', 'public-test-placeholder')
        self.assertIn('CLIENT_DNS_1=9.9.9.9\n', params)
        self.assertIn('ListenPort = 585\n', config)
        self.assertIn('Address = 10.66.66.1/24\n', config)
        self.assertIn('-s 10.66.66.0/24 -o ens3 -j MASQUERADE', config)
        self.assertNotIn('ip6tables', config)
        self.assertNotIn('SaveConfig', config)
        self.assertNotIn('::', config)
        headers = [int(v) for v in re.findall(r'^H[1-4] = (\d+)$', config, re.M)]
        self.assertEqual(len(set(headers)), 4)

    def test_invalid_address_dns_port_and_interface_are_rejected(self):
        for args in [('example.org', '585', '1.1.1.1'), ('203.0.113.10', '0', '1.1.1.1'),
                     ('203.0.113.10', '585', '1.1.1.1;echo unsafe')]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                setup.validate(*args)
        with self.assertRaises(ValueError):
            setup.configure('203.0.113.10', 585, '1.1.1.1', 'eth0;echo unsafe', '', '')


if __name__ == '__main__':
    unittest.main()

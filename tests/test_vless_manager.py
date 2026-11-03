"""Local isolated VLESS management tests. Never installs software or touches a VPS."""
import base64
import copy
import importlib.util
import json
import os
import stat
import hashlib
import io
import tarfile
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vless_manager', Path(__file__).resolve().parents[1] / 'server/vless_manager.py')
vless = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vless)


def key(number):
    return base64.urlsafe_b64encode(bytes([number]) * 32).decode().rstrip('=')


def fixture():
    return dict(schema=1, owner='Ashapp', address='203.0.113.10', port=443,
                sni='www.microsoft.com', fingerprint='chrome', private_key=key(1), public_key=key(2),
                clients=[dict(name='Phone', uuid='00000000-0000-4000-8000-000000000001', short_id='0123456789abcdef'),
                         dict(name='Laptop', uuid='00000000-0000-4000-8000-000000000002', short_id='1123456789abcdef')])


class VLESSTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'Requires POSIX permission semantics')
    def test_binary_and_ancestors_remain_executable_under_private_umask(self):
        from unittest.mock import MagicMock
        archive_name = 'sing-box-test-linux-amd64.tar.gz'
        data = io.BytesIO()
        binary = b'\x7fELFsynthetic-non-executable-fixture'
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            entry = tarfile.TarInfo('sing-box-test-linux-amd64/sing-box')
            entry.size = len(binary)
            archive.addfile(entry, io.BytesIO(binary))
        payload = data.getvalue()
        response = MagicMock()
        response.__enter__.return_value.read.return_value = payload
        path = self.directory / 'usr-local-lib' / 'ashapp' / 'sing-box'
        previous = os.umask(0o077)
        try:
            with patch.object(vless, 'BINARY', path), patch.object(vless.platform, 'machine', return_value='x86_64'), \
                    patch.dict(vless.RELEASES, {'x86_64': (archive_name, hashlib.sha256(payload).hexdigest())}), \
                    patch.object(vless.urllib.request, 'urlopen', return_value=response):
                vless.install_binary()
            self.assertEqual(path.read_bytes(), binary)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o755)
        finally:
            os.umask(previous)

    @unittest.skipIf(os.name == 'nt', 'Requires POSIX permission semantics')
    def test_restrictive_umask_keeps_new_service_ancestors_traversable(self):
        mask = os.umask(0o077)
        try:
            parent = self.directory / 'new-ancestor' / 'bin'
            vless.public_directory(parent)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(parent.parent.stat().st_mode), 0o755)
            self.install_fresh()
            self.assertEqual(stat.S_IMODE(self.manager.directory.stat().st_mode), 0o750)
        finally:
            os.umask(mask)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        # Model a traversable system ancestor, not a private user temp root.
        self.directory.chmod(0o755)
        self.calls, self.writes = [], []
        self.active = True
        self.failed_restart = False
        self.fail_validation = False
        self.manager = vless.VlessManager(self.directory, self.command, self.write, self.directory / 'unit')
        self.original = fixture()
        self.manager.state_path.write_text(vless.encoded(self.original))
        self.manager.config_path.write_text(vless.encoded(vless.server_config(self.original)))

    @unittest.skipIf(os.name == 'nt', 'Requires POSIX permission semantics')
    def test_old_private_service_ancestor_is_refused_without_widening_or_install(self):
        from unittest.mock import Mock
        private = self.directory / 'old-private-parent'
        private.mkdir(mode=0o700)
        manager = vless.VlessManager(private / 'vless', self.command, self.write, self.directory / 'new-unit')
        with patch.object(vless, 'install_binary') as install, patch.object(vless, 'probe_target') as probe:
            with self.assertRaisesRegex(RuntimeError, 'existing private'):
                manager.install('203.0.113.10', 24443, 'www.microsoft.com', 'chrome')
            install.assert_not_called()
            probe.assert_not_called()
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)

    def write(self, path, content, mode=0o600):
        self.writes.append((path, mode))
        path.write_text(content, encoding='utf-8')

    def command(self, args, data=None, check=True):
        self.calls.append(args)
        if 'check' in args and self.fail_validation:
            raise RuntimeError('Invalid candidate')
        if args[:2] == ['systemctl', 'restart'] and self.failed_restart:
            self.failed_restart = False
            raise RuntimeError('Simulated restart failure')
        code = 0 if self.active or args[:2] != ['systemctl', 'is-active'] else 3
        return subprocess.CompletedProcess(args, code, '', '')

    def test_export_is_allowlisted_and_never_contains_server_secrets(self):
        fields = ['Ignored display name', vless.SOURCE, self.original['clients'][0]['uuid']]
        result = self.manager.action('get-client', fields)
        connection = result['connection']
        self.assertEqual(set(connection), {'name', 'uuid', 'address', 'port', 'sni', 'public_key', 'short_id', 'fingerprint', 'flow'})
        self.assertEqual(connection['flow'], vless.FLOW)
        self.assertNotIn(key(1), json.dumps(result))
        self.assertEqual(self.manager.action('get-client', fields), result)
        self.assertFalse(self.calls)
        self.assertFalse(self.writes)

    def test_status_and_list_hide_uuid_until_explicit_export(self):
        # Identity is necessary in rows for scoped actions, but not status, names or stats.
        status = self.manager.status()
        self.assertTrue(status['vless'])
        self.assertNotIn(self.original['clients'][0]['uuid'], json.dumps(status))
        rows = self.manager.rows()
        self.assertEqual(rows[0]['source'], vless.SOURCE)
        self.assertFalse(rows[0]['can_import'])
        self.assertNotIn(key(1), json.dumps(rows))
        self.assertNotIn(key(2), json.dumps(rows))

    def test_add_uses_separate_uuid_short_id_and_restarts_only_own_service(self):
        self.manager.action('add-client', ['New phone', vless.SOURCE])
        state = self.manager.load()
        self.assertEqual(state['clients'][:2], self.original['clients'])
        self.assertEqual(len({c['uuid'] for c in state['clients']}), 3)
        self.assertEqual(len({c['short_id'] for c in state['clients']}), 3)
        self.assertTrue(any('check' in c for c in self.calls))
        services = [c[-1] for c in self.calls if c[0] == 'systemctl']
        self.assertEqual(set(services), {vless.SERVICE})
        self.assertFalse(any(c[0] in ('awg', 'wg', 'docker', 'iptables') for c in self.calls))

    def test_revoke_removes_only_selected_uuid_and_short_id(self):
        victim = self.original['clients'][0]
        self.manager.action('revoke-client', ['stale name', vless.SOURCE, victim['uuid']])
        state = self.manager.load()
        self.assertEqual(state['clients'], self.original['clients'][1:])
        config = self.manager.config_path.read_text()
        self.assertNotIn(victim['uuid'], config)
        self.assertNotIn(victim['short_id'], config)
        with self.assertRaisesRegex(ValueError, 'no longer exists'):
            self.manager.action('get-client', ['Phone', vless.SOURCE, victim['uuid']])

    def test_rename_preserves_access_and_duplicate_name_fails_without_writes(self):
        identity = self.original['clients'][0]['uuid']
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.manager.action('rename-client', ['Phone', vless.SOURCE, identity, 'Laptop'])
        self.assertFalse(self.writes)
        self.manager.action('rename-client', ['Phone', vless.SOURCE, identity, 'Renamed'])
        client = self.manager.load()['clients'][0]
        self.assertEqual(client, {**self.original['clients'][0], 'name': 'Renamed'})

    def test_validation_failure_preserves_config_without_restarting(self):
        self.fail_validation = True
        with self.assertRaises(RuntimeError):
            self.manager.action('add-client', ['New', vless.SOURCE])
        self.assertEqual(self.manager.load(), self.original)
        self.assertFalse(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))

    def test_restart_failure_restores_state_config_and_service(self):
        self.failed_restart = True
        with self.assertRaises(RuntimeError):
            self.manager.action('revoke-client', ['Phone', vless.SOURCE, self.original['clients'][0]['uuid']])
        self.assertEqual(self.manager.load(), self.original)
        self.assertEqual(sum(c[:2] == ['systemctl', 'restart'] for c in self.calls), 2)
        self.assertTrue((self.directory / 'recovery-state.json').exists())

    def test_stopped_service_clients_can_be_changed_without_starting_it(self):
        self.active = False
        self.manager.action('add-client', ['New', vless.SOURCE])
        self.assertEqual(len(self.manager.load()['clients']), 3)
        self.assertFalse(any(c[:2] == ['systemctl', 'restart'] for c in self.calls))

    def test_manually_changed_config_is_never_overwritten(self):
        config = vless.server_config(self.original)
        config['inbounds'][0]['listen_port'] = 8443
        self.manager.config_path.write_text(vless.encoded(config))
        with self.assertRaisesRegex(RuntimeError, 'outside Ashapp'):
            self.manager.action('add-client', ['New', vless.SOURCE])
        self.assertFalse(self.writes)

    def test_interrupted_transaction_blocks_further_changes_and_reports_attention(self):
        self.manager.pending_path.write_text('Interrupted transaction')
        with self.assertRaisesRegex(RuntimeError, 'interrupted'):
            self.manager.action('revoke-client', ['Phone', vless.SOURCE, self.original['clients'][0]['uuid']])
        self.assertIn('vless_error', self.manager.status())
        self.assertFalse(self.writes)

    def test_simulated_process_death_preserves_pending_marker_and_recovery(self):
        writer = self.manager.writer
        def interrupt(path, content, mode=0o600):
            if path == self.manager.state_path:
                raise KeyboardInterrupt('Simulated process death')
            writer(path, content, mode)
        self.manager.writer = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.manager.action('add-client', ['New', vless.SOURCE])
        self.assertTrue(self.manager.pending_path.exists())
        self.assertTrue((self.directory / 'recovery-state.json').exists())
        with self.assertRaisesRegex(RuntimeError, 'interrupted'):
            self.manager.load()

    def test_repeated_setup_preserves_settings_keys_and_clients(self):
        with patch.object(vless, 'install_binary') as install:
            result = self.manager.install('203.0.113.99', '8443', 'www.example.com', 'firefox')
        self.assertTrue(result['preserved'])
        install.assert_not_called()
        self.assertEqual(self.manager.load(), self.original)

    def test_install_rejects_occupied_dedicated_directory_without_mutating(self):
        self.manager.state_path.unlink()
        with patch.object(vless, 'install_binary') as install:
            with self.assertRaisesRegex(RuntimeError, 'occupied'):
                self.manager.install('203.0.113.10', '443', 'www.microsoft.com', 'chrome')
        install.assert_not_called()
        self.assertFalse(self.writes)

    def test_invalid_inputs_and_unknown_operations_are_rejected(self):
        for field, value in [('sni', 'https://bad'), ('port', 0), ('port', True), ('public_key', 'bad'), ('fingerprint', 'unsafe')]:
            state = copy.deepcopy(self.original); state[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                vless.checked_state(state)
        with self.assertRaises(ValueError):
            self.manager.action('import-client', ['Phone', vless.SOURCE, 'bad'])
        for record in ['bad', {}, {'name': 'Device', 'uuid': 'bad', 'short_id': []}]:
            state = copy.deepcopy(self.original); state['clients'] = [record]
            with self.subTest(record=record), self.assertRaises(ValueError):
                vless.checked_state(state)

    def test_recovery_file_cleanup_failure_does_not_misreport_revocation(self):
        unlink = Path.unlink
        def fail_recovery(path, *args, **kwargs):
            if path.name == 'recovery-state.json':
                raise PermissionError('Simulated cleanup error')
            return unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail_recovery):
            result = self.manager.action('revoke-client', ['Phone', vless.SOURCE, self.original['clients'][0]['uuid']])
        self.assertTrue(result['revoked'])
        self.assertIn('cleanup', result['warning'])
        self.assertEqual(self.manager.load()['clients'], self.original['clients'][1:])

    def test_install_download_hash_is_checked_before_extraction(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'corrupted archive'
        with patch.object(vless.platform, 'machine', return_value='x86_64'), patch.object(vless.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(RuntimeError, 'checksum'):
                vless.install_binary()

    def test_target_probe_keeps_tls_verification_and_tries_ipv4_after_ipv6_failure(self):
        from unittest.mock import MagicMock
        addresses = [(None, None, None, None, ('2001:4860:4860::8888', 443)),
                     (None, None, None, None, ('1.1.1.1', 443))]
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.selected_alpn_protocol.return_value = 'h2'
        connection = MagicMock()
        with patch.object(vless.socket, 'getaddrinfo', return_value=addresses), \
             patch.object(vless.socket, 'create_connection', side_effect=[OSError('No IPv6 route'), connection]) as connect, \
             patch.object(vless.ssl, 'create_default_context', return_value=context):
            vless.probe_target('www.microsoft.com')
        self.assertEqual(context.minimum_version, vless.ssl.TLSVersion.TLSv1_3)
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], 'www.microsoft.com')
        self.assertNotIn('verify_mode', context.__dict__)

    def test_target_resolving_to_private_network_is_rejected_without_connecting(self):
        with patch.object(vless.socket, 'getaddrinfo', return_value=[(None, None, None, None, ('127.0.0.1', 443))]), \
             patch.object(vless.socket, 'create_connection') as connect:
            with self.assertRaisesRegex(ValueError, 'public addresses'):
                vless.probe_target('www.microsoft.com')
        connect.assert_not_called()

    def test_fresh_install_uses_own_service_unprivileged_account_and_port_rule(self):
        self.install_fresh()
        self.assertTrue(self.manager.status()['vless'])
        self.assertTrue(self.manager.state_path.exists())
        self.assertFalse(self.manager.pending_path.exists())
        unit = self.manager.unit.read_text()
        self.assertIn('User=ashapp-vless', unit)
        self.assertIn('NoNewPrivileges=true', unit)
        self.assertIn('--dport 24443', self.firewall.read_text())
        self.assertFalse(any('awg' in str(c) or 'docker' in c for c in self.calls))
        self.assertIn((self.manager.state_path, 0o600), self.writes)
        self.assertIn((self.manager.config_path, 0o640), self.writes)

    def test_failed_initial_start_removes_only_new_service_and_allows_retry(self):
        self.failed_restart = True
        with self.assertRaisesRegex(RuntimeError, 'New service files were removed'):
            self.install_fresh()
        self.assertFalse(self.manager.directory.exists())
        self.assertFalse(self.manager.unit.exists())
        self.assertFalse(self.binary.exists())
        self.assertFalse(self.firewall.exists())
        self.assertTrue((self.directory / 'unrelated.txt').exists())

    def install_fresh(self):
        from unittest.mock import Mock
        self.manager = vless.VlessManager(self.directory / 'fresh', self.install_command, self.write, self.directory / 'vless.service')
        self.binary, self.firewall = self.directory / 'sing-box', self.directory / 'port-rule'
        (self.directory / 'unrelated.txt').write_text('preserve')
        self.active = False
        with patch.object(vless, 'BINARY', self.binary), patch.object(vless, 'FIREWALL', self.firewall), \
             patch.object(vless, 'probe_target'), patch.object(vless, 'install_binary', side_effect=lambda: self.binary.write_bytes(b'test-binary')), \
             patch.object(vless.socket, 'socket', return_value=Mock(__enter__=Mock(return_value=Mock()), __exit__=Mock(return_value=False))):
            return self.manager.install('203.0.113.10', 24443, 'www.microsoft.com', 'chrome')

    def install_command(self, args, data=None, check=True):
        if args[:3] == [str(self.binary), 'generate', 'reality-keypair']:
            return subprocess.CompletedProcess(args, 0, f'PrivateKey: {key(1)}\nPublicKey: {key(2)}\n', '')
        if args[:2] == ['getent', 'passwd']:
            return subprocess.CompletedProcess(args, 2, '', '')
        if args[:2] == ['systemctl', 'restart']:
            if not self.failed_restart:
                self.active = True
        if args[:3] == ['systemctl', 'disable', '--now']:
            self.active = False
        return self.command(args, data, check)


if __name__ == '__main__':
    unittest.main()

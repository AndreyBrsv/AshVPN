"""Local regression checks. No SSH connections or privileged commands are run."""
import importlib.util
import base64
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

if sys.platform == "win32":
    sys.modules.setdefault("fcntl", types.ModuleType("fcntl"))
spec = importlib.util.spec_from_file_location(
    "clients", Path(__file__).resolve().parents[1] / "server" / "clients.py")
clients = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clients)


class ClientTests(unittest.TestCase):
    def test_same_named_docker_image_does_not_break_server_status(self):
        from unittest.mock import Mock
        calls = []

        def commands(args, data=None, check=True):
            calls.append(args)
            if args[:2] == ['docker', 'inspect']:
                typed = args[2:4] == ['--type', 'container']
                return subprocess.CompletedProcess(args, 1 if typed else 0,
                                                   '' if typed else json.dumps([{'Id': 'image-fixture'}]), '')
            if args[:2] == ['sh', '-c']:
                return subprocess.CompletedProcess(args, 0, '', '')
            return subprocess.CompletedProcess(args, 1, '', '')

        self.run.side_effect = commands
        manager = Mock()
        manager.status.return_value = {'vless': False, 'vless_configured': False}
        with patch.object(clients, 'vless_manager', return_value=manager), \
                patch.object(clients, 'amnezia_containers', return_value=[]):
            result = clients.status()
        self.assertFalse(result['socks5'])
        self.assertNotIn('socks5_configured', result)
        self.assertIn(['docker', 'inspect', '--type', 'container', clients.SOCKS_NAME], calls)

    def test_private_socks_requires_supported_stable_daemon_not_client_version(self):
        allowed = ('28.0.0', '29.1.2', '28.2.2-0ubuntu1~24.04.1', '28.0.1+dfsg1', '28.0.1+azure-1')
        refused = ('27.5.1', '20.10.24', '', 'unknown', '28.0', '28.0.0-rc.1', '29.0.0-beta1',
                   '28.0.0-1dev', '28.0.0-custom', '28.0.0\n27.0.0')
        for version in allowed + refused:
            with self.subTest(version=version):
                self.run.return_value = subprocess.CompletedProcess([], 0, version, '')
                self.run.side_effect = None
                if version in allowed:
                    self.assertTrue(clients.require_private_socks_engine()['private_socks_ready'])
                else:
                    with self.assertRaisesRegex(RuntimeError, 'Docker Engine 28'):
                        clients.require_private_socks_engine()
                self.run.assert_called_with(['docker', 'version', '--format', '{{.Server.Version}}'], check=False)
        self.run.return_value = subprocess.CompletedProcess([], 1, '29.0.0', 'unavailable')
        with self.assertRaisesRegex(RuntimeError, 'Docker Engine 28'):
            clients.require_private_socks_engine()
        self.run.side_effect = FileNotFoundError('docker')
        with self.assertRaisesRegex(RuntimeError, 'Docker Engine 28'):
            clients.require_private_socks_engine()

    def socks_commands(self, args, data=None, check=True):
        if args[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(args, 0, json.dumps([self.socks_container]), '')
        if args[:2] == ['docker', 'exec']:
            return subprocess.CompletedProcess(args, 0, 'users test:CL:test_placeholder\nsocks -p1080\n', '')
        if args[:2] == ['docker', 'version']:
            return subprocess.CompletedProcess(args, 0, getattr(self, 'engine_version', '27.5.1') + '\n', '')
        return subprocess.CompletedProcess(args, 1 if args[0] != 'docker' else 0, '', '')

    def test_unsupported_private_details_and_activation_are_refused_but_stop_and_public_remain(self):
        self.socks_container = {'HostConfig': {'PortBindings': {'1080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '1080'}]}},
                                'NetworkSettings': {'Ports': {}}, 'State': {'Running': False}}
        self.run.side_effect = self.socks_commands
        with self.assertRaisesRegex(RuntimeError, 'Docker Engine 28'):
            clients.socks_info()
        for operation in ('start', 'restart'):
            self.run.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'Docker Engine 28'):
                clients.service_control('socks', operation)
            self.assertNotIn(unittest.mock.call(['docker', operation, clients.SOCKS_NAME]), self.run.call_args_list)
        self.run.reset_mock()
        self.assertTrue(clients.service_control('socks', 'stop')['ok'])
        self.assertNotIn(unittest.mock.call(['docker', 'version', '--format', '{{.Server.Version}}'], check=False), self.run.call_args_list)
        for wildcard in ('0.0.0.0', '', '::'):
            self.socks_container['HostConfig']['PortBindings']['1080/tcp'][0]['HostIp'] = wildcard
            self.socks_container['NetworkSettings']['Ports'] = {'1080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '1080'}]}
            self.assertEqual(clients.socks_info()['access'], 'public')
            self.assertTrue(clients.service_control('socks', 'start')['ok'])
        self.socks_container['HostConfig']['PortBindings']['1080/tcp'][0]['HostIp'] = '127.0.0.1'
        self.engine_version = '28.0.0'
        self.assertEqual(clients.socks_info()['access'], 'private')
        self.assertTrue(clients.service_control('socks', 'start')['ok'])

    def test_unsupported_private_status_preserves_other_protocols_and_stopped_bindings(self):
        self.socks_container = {'HostConfig': {'PortBindings': {'1080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '1080'}]}},
                                'NetworkSettings': {'Ports': {}}, 'State': {'Running': False}}
        def status_run(args, data=None, check=True):
            if args[:2] == ['sh', '-c']:
                return subprocess.CompletedProcess(args, 0, '', '')
            return self.socks_commands(args, data, check)
        self.run.side_effect = status_run
        manager = unittest.mock.Mock()
        manager.status.return_value = {'vless': True}
        with patch.object(clients, 'vless_manager', return_value=manager), patch.object(clients, 'amnezia_containers', return_value=[]):
            result = clients.status()
        self.assertTrue(result['vless'])
        self.assertTrue(result['socks5_configured'])
        self.assertFalse(result['socks5'])
        self.assertEqual(result['socks5_port'], 1080)
        self.assertFalse(result['socks5_private_supported'])
        self.assertIn('Docker Engine 28', result['socks5_access_warning'])
        self.socks_container['HostConfig']['PortBindings']['1080/tcp'][0]['HostIp'] = ''
        with patch.object(clients, 'vless_manager', return_value=manager), patch.object(clients, 'amnezia_containers', return_value=[]):
            result = clients.status()
        self.assertTrue(result['vless'])
        self.assertEqual(result['socks5_access'], 'public')

    def test_vless_actions_route_by_source_and_uuid_without_host_mutations(self):
        from unittest.mock import Mock
        manager = Mock()
        fields = ['Same name', 'vless-reality', '00000000-0000-4000-8000-000000000001']
        manager.action.return_value = {'revoked': True}
        with patch.object(clients, 'vless_manager', return_value=manager):
            self.assertEqual(clients.client_action('revoke-client', fields), {'revoked': True})
        manager.action.assert_called_once_with('revoke-client', fields)
        self.sync.assert_not_called()

    def test_socks_authentication_accepts_fragmented_tcp_replies(self):
        from unittest.mock import MagicMock
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [b'\x05', b'\x02', b'\x01', b'\x00']
        with patch.object(clients, 'socks_info', return_value={
                'port': 1080, 'user': 'test', 'password': 'placeholder'}), \
                patch.object(clients.socket, 'create_connection', return_value=sock):
            self.assertEqual(clients.socks_check(), {'ok': True})

    def test_socks_eof_is_not_treated_as_success(self):
        from unittest.mock import Mock
        with self.assertRaises(OSError):
            clients.recv_exact(Mock(recv=Mock(return_value=b'')), 2)

    def test_corrupt_vpn_settings_do_not_block_other_server_management(self):
        (self.awg / 'params').write_text('invalid')
        self.config.write_text('invalid')
        with patch.object(clients, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')):
            result = clients.status()
        self.assertTrue(result['awg_configured'])
        self.assertIn('awg_error', result)
        self.assertFalse(result['awg'])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ashapp_review_")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.awg = self.root / "awg"
        self.awg.mkdir()
        self.exports = self.root / "clients"
        for name, value in (("AWG_DIR", self.awg), ("CLIENTS_DIR", self.exports)):
            active = patch.object(clients, name, value)
            active.start()
            self.addCleanup(active.stop)
        self.config = self.awg / "awg0.conf"
        self.original = (
            "[Interface]\nAddress = 10.0.0.1/29\nListenPort = 585\n"
            "PrivateKey = server-test-placeholder\nJc = 4\n"
            "### Client alice\n[Peer]\nPublicKey = alice-test-placeholder\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "[Peer]\nPublicKey = unmarked-test-placeholder\nAllowedIPs = 10.0.0.3/32\n")
        self.config.write_text(self.original)
        (self.awg / "params").write_text(
            "SERVER_AWG_NIC=awg0\nSERVER_PUB_IP=2001:db8::1\nCLIENT_DNS_1=1.1.1.1\n")
        self.kernel = patch.object(clients, "verified_kernel", return_value=True).start()
        self.addCleanup(patch.stopall)
        self.apply_peer = clients.apply_peer
        self.sync = patch.object(clients, "apply_peer").start()
        self.runtime = patch.object(clients, 'runtime_peers', return_value={}).start()
        self.run = patch.object(clients, "run", side_effect=self.fake_run).start()

    def fake_run(self, args, data=None, check=True):
        return subprocess.CompletedProcess(args, 0, "test-key-placeholder\n", "")

    def test_ipv6_endpoint_is_bracketed(self):
        clients.add_client("bob")
        exported = (self.exports / "awg0-client-bob.conf").read_text()
        self.assertIn("Endpoint = [2001:db8::1]:585", exported)

    def test_unmarked_peer_addresses_are_reserved(self):
        clients.add_client("bob")
        exported = (self.exports / "awg0-client-bob.conf").read_text()
        self.assertIn("Address = 10.0.0.4/32", exported)
        self.assertIn("PublicKey = unmarked-test-placeholder", self.config.read_text())

    def test_runtime_only_peer_routes_are_reserved_and_only_new_peer_is_applied(self):
        self.runtime.return_value = {'external': {'PublicKey': 'external', 'AllowedIPs': '10.0.0.4/32'}}
        clients.add_client('bob')
        self.assertIn('Address = 10.0.0.5/32', (self.exports / 'awg0-client-bob.conf').read_text())
        self.assertEqual(self.sync.call_args.args[1], 'test-key-placeholder')
        self.assertNotIn('external', self.sync.call_args.args[2].values())

    def test_peer_application_merges_selected_peer_and_preserves_live_foreign_peer(self):
        selected = dict(PublicKey='selected', AllowedIPs='10.0.0.4/32')
        peers = {'external': dict(PublicKey='external', AllowedIPs='10.0.0.5/32')}
        def run(args, data=None, check=True):
            if args[:2] == ['awg', 'addconf']:
                peers['selected'] = clients.assignments(data)
            elif args[:2] == ['awg', 'set']:
                peers.pop(args[4], None)
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(clients, 'run', side_effect=run), patch.object(clients, 'runtime_peers', side_effect=lambda _: peers), \
                patch.object(clients, 'apply_peer', self.apply_peer):
            clients.apply_peer('awg0', 'selected', selected)
            clients.apply_peer('awg0', 'selected', None)
        self.assertEqual(set(peers), {'external'})

    def test_routed_network_does_not_get_reassigned_to_a_client(self):
        original = self.original.replace("10.0.0.3/32", "10.0.0.0/29")
        self.config.write_text(original)
        with self.assertRaisesRegex(RuntimeError, "addresses"):
            clients.add_client("bob")
        self.assertEqual(self.config.read_text(), original)
        self.assertFalse(self.exports.exists())

    def test_failed_sync_restores_config_and_removes_client_export(self):
        self.sync.side_effect = [RuntimeError("sync failed"), None]
        with self.assertRaises(RuntimeError):
            clients.add_client("bob")
        self.assertEqual(self.config.read_text(), self.original)
        self.assertFalse((self.exports / "awg0-client-bob.conf").exists())

    def test_revoke_keeps_the_unmarked_peer(self):
        # A client created by a different tool may have no local export.
        with patch.object(clients, "client_path", side_effect=RuntimeError("missing")):
            clients.revoke_client("alice")
        text = self.config.read_text()
        self.assertIn("PublicKey = unmarked-test-placeholder", text)
        self.assertNotIn("PublicKey = alice-test-placeholder", text)

    def test_failed_revoke_restores_config(self):
        self.sync.side_effect = [RuntimeError("sync failed"), None]
        with self.assertRaises(RuntimeError):
            clients.revoke_client("alice")
        self.assertEqual(self.config.read_text(), self.original)

    def test_host_client_identity_is_checked_before_revoke(self):
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            clients.client_action('revoke-client', ['alice', 'awg0', 'wrong-public-placeholder'])
        self.assertEqual(self.config.read_text(), self.original)
        self.sync.assert_not_called()

    def test_host_rename_preserves_unmarked_peer_and_does_not_restart_vpn(self):
        clients.client_action('rename-client', ['alice', 'awg0', 'alice-test-placeholder', 'phone'])
        text = self.config.read_text()
        self.assertIn('### Client phone', text)
        self.assertIn('PublicKey = alice-test-placeholder', text)
        self.assertIn('PublicKey = unmarked-test-placeholder', text)
        self.sync.assert_not_called()

    def test_rename_rejects_edit_during_export_creation_without_losing_peer(self):
        self.exports.mkdir()
        previous = self.exports / 'awg0-client-alice.conf'
        previous.write_text('private-export-fixture')
        concurrent = self.original + '\n[Peer]\nPublicKey = external-fixture\nAllowedIPs = 10.0.0.6/32\n'
        write = clients.atomic_write
        def change_during_export(path, text, mode=0o600):
            write(path, text, mode)
            if path.name == 'awg0-client-phone.conf':
                self.config.write_text(concurrent)
        with patch.object(clients, 'atomic_write', side_effect=change_during_export), self.assertRaisesRegex(RuntimeError, 'changed concurrently'):
            clients.rename_client('alice', 'phone')
        self.assertEqual(self.config.read_text(), concurrent)
        self.assertTrue(previous.exists())
        self.assertFalse((self.exports / 'awg0-client-phone.conf').exists())

    def test_rename_recovery_preserves_concurrent_edit_and_both_exports(self):
        self.exports.mkdir()
        previous = self.exports / 'awg0-client-alice.conf'
        previous.write_text('private-export-fixture')
        unlink = Path.unlink
        def fail_cleanup(path, *args, **kwargs):
            if path == previous:
                self.config.write_text(self.config.read_text() + '\n# concurrent external edit\n')
                raise PermissionError('fixture-denied')
            return unlink(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail_cleanup), self.assertRaisesRegex(RuntimeError, 'Concurrent edits'):
            clients.rename_client('alice', 'phone')
        self.assertIn('# concurrent external edit', self.config.read_text())
        self.assertIn('### Client phone', self.config.read_text())
        self.assertEqual(previous.read_text(), 'private-export-fixture')
        self.assertEqual((self.exports / 'awg0-client-phone.conf').read_text(), 'private-export-fixture')

    def test_importing_host_config_saves_existing_key_without_vpn_changes(self):
        def key(number):
            return base64.b64encode(bytes([number]) * 32).decode()
        original = self.original.replace('server-test-placeholder', key(1)).replace('alice-test-placeholder', key(2))
        self.config.write_text(original)
        content = ('[Interface]\nPrivateKey = ' + key(4) + '\nAddress = 10.0.0.2/32\n'
                   '[Peer]\nPublicKey = ' + key(5) + '\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:585\n')
        def derive(args, data=None, check=True):
            self.assertEqual(args, ['awg', 'pubkey'])
            value = key(2) if data.strip() == key(4) else key(5)
            return subprocess.CompletedProcess(args, 0, value + '\n', '')
        with patch.object(clients, 'run', side_effect=derive):
            clients.client_action('import-client', ['alice', 'awg0', key(2), content, 'no'])
            self.assertEqual(clients.get_client('alice')['config'], content)
        self.assertEqual(self.config.read_text(), original)
        self.sync.assert_not_called()

    def test_revocation_reports_export_cleanup_failure_separately(self):
        from unittest.mock import Mock
        export = Mock()
        export.unlink.side_effect = PermissionError('denied')
        with patch.object(clients, 'client_path', return_value=export):
            result = clients.revoke_client('alice')
        self.assertTrue(result['revoked'])
        self.assertIn('could not be erased', result['warning'])

    def test_host_import_rejects_wrong_endpoint_port(self):
        def key(number):
            return base64.b64encode(bytes([number]) * 32).decode()
        self.config.write_text(self.original.replace('server-test-placeholder', key(1)).replace('alice-test-placeholder', key(2)))
        content = ('[Interface]\nPrivateKey = ' + key(4) + '\nAddress = 10.0.0.2/32\n'
                   '[Peer]\nPublicKey = ' + key(5) + '\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:9999\n')
        def derive(args, data=None, check=True):
            return subprocess.CompletedProcess(args, 0, (key(2) if data.strip() == key(4) else key(5)) + '\n', '')
        with patch.object(clients, 'run', side_effect=derive):
            with self.assertRaisesRegex(RuntimeError, 'endpoint port'):
                clients.import_client_configuration('alice', key(2), content)


if __name__ == "__main__":
    unittest.main()

"""Local regression checks. No SSH connections or privileged commands are run."""
import importlib.util
import base64
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
        self.sync = patch.object(clients, "sync").start()
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

    def test_routed_network_does_not_get_reassigned_to_a_client(self):
        original = self.original.replace("10.0.0.3/32", "10.0.0.0/29")
        self.config.write_text(original)
        with self.assertRaisesRegex(RuntimeError, "addresses"):
            clients.add_client("bob")
        self.assertEqual(self.config.read_text(), original)
        self.assertFalse(self.exports.exists())

    def test_failed_sync_restores_config_and_removes_client_export(self):
        self.sync.side_effect = RuntimeError("sync failed")
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
        self.sync.side_effect = RuntimeError("sync failed")
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


if __name__ == "__main__":
    unittest.main()

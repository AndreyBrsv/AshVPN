"""Read-only discovery of existing deployments; no Docker, SSH or root commands run."""
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

if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
spec = importlib.util.spec_from_file_location(
    'inventory_clients', Path(__file__).resolve().parents[1] / 'server' / 'clients.py')
clients = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clients)

HEADER = 'private-test-placeholder\tpublic-test-placeholder\t585\toff\n'
CONFIG = ('[Interface]\nPrivateKey = private-test-placeholder\nListenPort = 585\n'
          '[Peer]\nPublicKey = alice-public-placeholder\n'
          'PresharedKey = preshared-test-placeholder\nAllowedIPs = 10.8.0.2/32\n')


class VpnInventoryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        p = patch.object(clients, 'AWG_DIR', self.directory)
        p.start()
        self.addCleanup(p.stop)
        self.tables = {}
        self.configs = {}
        self.containers = {}
        self.calls = []
        self.stats = HEADER + ('alice-public-placeholder\tpreshared-test-placeholder\t(none)\t'
                               '10.8.0.2/32\t1234\t50\t60\t25\n')
        self.docker_error = False
        self.stats_error = False
        p = patch.object(clients, 'run', side_effect=self.run_command)
        p.start()
        self.addCleanup(p.stop)

    def run_command(self, args, data=None, check=True):
        self.calls.append(args)
        code, output = 1, ''
        if args[:3] == ['docker', 'container', 'ls']:
            code, output = (1 if self.docker_error else 0), '\n'.join(self.containers)
        elif args[:2] == ['docker', 'inspect']:
            code, output = 0, json.dumps({'Running': self.containers[args[-1]]})
        elif args[:2] == ['docker', 'exec']:
            name = args[2]
            if args[3] == 'cat':
                text = (self.tables if args[4].endswith('clientsTable') else self.configs).get(name)
                code, output = (0, text) if text is not None else (1, '')
            elif args[3] in ('awg', 'wg'):
                code, output = (1 if self.stats_error else 0), self.stats
        elif args[:2] == ['awg', 'show']:
            code, output = (1 if self.stats_error else 0), self.stats
        return subprocess.CompletedProcess(args, code, output, '')

    def external(self, name='amnezia-awg', legacy=False):
        self.containers[name] = True
        self.configs[name] = CONFIG
        self.tables[name] = json.dumps(
            {'alice-public-placeholder': {'clientName': 'Alice phone'}} if legacy else
            [{'clientId': 'alice-public-placeholder', 'userData': {'clientName': 'Alice phone'}}])

    def test_both_official_container_versions_and_table_schemas_are_read_without_mutation(self):
        self.external(legacy=True)
        self.external('amnezia-awg2')
        result = clients.list_clients()
        self.assertEqual([c['name'] for c in result['clients']], ['Alice phone', 'Alice phone'])
        self.assertEqual({c['source'] for c in result['clients']}, {'amnezia-awg', 'amnezia-awg2'})
        self.assertFalse(result['warnings'])
        for row in result['clients']:
            self.assertEqual((row['handshake'], row['rx'], row['tx']), (1234, 50, 60))
            self.assertFalse(row['can_revoke'])
            self.assertFalse(row['can_export'])
        self.assertIn(['docker', 'exec', 'amnezia-awg', 'wg', 'show', 'wg0', 'dump'], self.calls)
        self.assertIn(['docker', 'exec', 'amnezia-awg2', 'awg', 'show', 'awg0', 'dump'], self.calls)
        for command in self.calls:
            if command[0] == 'docker':
                self.assertIn(command[1], ('container', 'inspect', 'exec'))
                if command[1] == 'exec':
                    self.assertIn(command[3], ('cat', 'wg', 'awg'))
        serialized = json.dumps(result)
        self.assertNotIn('private-test-placeholder', serialized)
        self.assertNotIn('preshared-test-placeholder', serialized)

    def test_no_params_or_markers_required_to_show_saved_host_peers(self):
        path = self.directory / 'awg0.conf'
        path.write_text(CONFIG)
        self.stats_error = True
        with patch.object(clients, 'verified_kernel', return_value=False):
            result = clients.list_clients()
        self.assertEqual(result['clients'][0]['public_key'], 'alice-public-placeholder')
        self.assertFalse(result['clients'][0]['stats_available'])
        self.assertFalse(result['clients'][0]['can_revoke'])
        self.assertIn('statistics unavailable', result['warnings'][0])
        self.assertEqual(path.read_text(), CONFIG)

    def test_stopped_managed_host_preserves_name_and_export_without_enabling_revoke(self):
        (self.directory / 'params').write_text('SERVER_AWG_NIC=awg0\n')
        (self.directory / 'awg0.conf').write_text(CONFIG.replace('[Peer]', '### Client alice\n[Peer]'))
        self.stats_error = True
        with patch.object(clients, 'verified_kernel', return_value=False), \
                patch.object(clients, 'client_path', return_value=Path('synthetic-test-export')):
            row = clients.list_clients()['clients'][0]
        self.assertEqual(row['name'], 'alice')
        self.assertTrue(row['can_export'])
        self.assertFalse(row['can_revoke'])

    def test_unmarked_peer_is_not_hidden_next_to_managed_peer(self):
        (self.directory / 'awg0.conf').write_text(CONFIG.replace('[Peer]', '### Client alice\n[Peer]') +
                                                  '[Peer]\nPublicKey = other-public-placeholder\nAllowedIPs = 10.8.0.3/32\n')
        with patch.object(clients, 'verified_kernel', return_value=True):
            rows = clients.list_clients()['clients']
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['name'], 'alice')
        self.assertEqual(rows[1]['public_key'], 'other-public-placeholder')
        self.assertFalse(rows[1]['can_revoke'])

    def test_malformed_or_missing_names_fall_back_to_real_peers(self):
        for table in ('invalid json', None, '42'):
            with self.subTest(table=table):
                self.external()
                self.tables['amnezia-awg'] = table
                result = clients.list_clients()
                self.assertEqual(len(result['clients']), 1)
                self.assertEqual(result['clients'][0]['public_key'], 'alice-public-placeholder')
                self.assertTrue(result['warnings'])

    def test_metadata_only_entry_is_marked_as_not_configured(self):
        self.external()
        self.tables['amnezia-awg'] = json.dumps([
            {'clientId': 'missing-public-placeholder', 'userData': {'clientName': 'Old device'}}])
        rows = clients.list_clients()['clients']
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]['name'], 'Old device')
        self.assertFalse(rows[1]['configured'])
        self.assertFalse(rows[1]['can_revoke'])

    def test_stopped_container_is_reported_without_starting_or_exec(self):
        self.external()
        self.containers['amnezia-awg'] = False
        result = clients.list_clients()
        self.assertFalse(result['clients'])
        self.assertIn('container is stopped', result['warnings'][0])
        self.assertFalse(any(c[:2] == ['docker', 'exec'] for c in self.calls))

    def test_docker_discovery_failure_is_not_a_successful_empty_list(self):
        self.docker_error = True
        result = clients.list_clients()
        self.assertFalse(result['clients'])
        self.assertIn('discovery failed', result['warnings'][0])
        status = clients.status()
        self.assertIn('vpn_detection_error', status)

    def test_container_detection_marks_vpn_configured_without_claiming_host_kernel(self):
        self.external()
        result = clients.status()
        self.assertTrue(result['awg_configured'])
        self.assertFalse(result['awg_host_configured'])
        self.assertFalse(result['awg'])
        self.assertFalse(result['kernel'])
        self.assertEqual(result['external_awg'][0]['source'], 'amnezia-awg')

    def test_runtime_peer_missing_from_saved_config_is_shown(self):
        self.external()
        self.configs['amnezia-awg'] = '[Interface]\n'
        self.tables['amnezia-awg'] = '[]'
        row = clients.list_clients()['clients'][0]
        self.assertEqual(row['addresses'], '10.8.0.2/32')
        self.assertTrue(row['configured'])

    def test_existing_valid_container_peer_can_be_renamed_and_revoked_without_private_export(self):
        self.external()
        public = base64.b64encode(bytes([2]) * 32).decode()
        self.configs['amnezia-awg'] = CONFIG.replace('alice-public-placeholder', public)
        self.stats = self.stats.replace('alice-public-placeholder', public)
        self.tables['amnezia-awg'] = json.dumps([{'clientId': public, 'userData': {'clientName': 'Phone'}}])
        with patch.object(clients, 'CLIENTS_DIR', self.directory / 'private'):
            row = clients.list_clients()['clients'][0]
        self.assertTrue(row['can_rename'])
        self.assertTrue(row['can_revoke'])
        self.assertFalse(row['can_export'])


if __name__ == '__main__':
    unittest.main()

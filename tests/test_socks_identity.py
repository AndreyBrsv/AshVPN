"""SOCKS snapshots refer to the same real service in both managers; no Docker."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
spec = importlib.util.spec_from_file_location('socks_identity_clients', Path(__file__).resolve().parents[1] / 'server/clients.py')
clients = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clients)


class SocksIdentityTests(unittest.TestCase):
    def setUp(self):
        self.container = {
            'Id': 'a' * 64,
            'State': {'Running': True},
            'Config': {'Labels': {}},
            'HostConfig': {'PortBindings': {'1080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': ''}]}},
            'NetworkSettings': {'Ports': {'1080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '49152'}]}},
        }
        self.commands = []

    def command(self, args, data=None, check=True):
        self.commands.append(args)
        if args[:4] == ['docker', 'inspect', '--type', 'container']:
            return subprocess.CompletedProcess(args, 0, json.dumps([self.container]), '')
        if args[:2] == ['docker', 'exec']:
            self.assertEqual(args[2], 'a' * 64, 'Read credentials from the captured container ID.')
            return subprocess.CompletedProcess(args, 0, 'users synthetic:CL:synthetic_placeholder\nsocks -p1080\n', '')
        if args[:2] == ['sh', '-c']:
            return subprocess.CompletedProcess(args, 0, '', '')
        if args == ['/usr/sbin/sshd', '-T']:
            return subprocess.CompletedProcess(args, 0, 'permitrootlogin yes\npasswordauthentication yes\n', '')
        return subprocess.CompletedProcess(args, 1, '', '')

    def test_running_proxy_exports_allocated_runtime_port_and_captured_identity(self):
        with patch.object(clients, 'run', side_effect=self.command):
            details = clients.socks_info()
        self.assertEqual(details['port'], 49152)
        self.assertEqual(details['source'], 'amnezia-socks5proxy')
        self.assertEqual(details['container_id'], 'a' * 64)
        self.assertEqual(details['user'], 'synthetic')

    def test_container_replacement_cannot_mix_old_credentials_with_new_endpoint(self):
        def replace_after_read(args, data=None, check=True):
            response = self.command(args, data, check)
            if args[:2] == ['docker', 'exec']:
                self.container = copy.deepcopy(self.container)
                self.container['Id'] = 'b' * 64
                self.container['NetworkSettings']['Ports']['1080/tcp'][0]['HostPort'] = '2080'
            return response

        with patch.object(clients, 'run', side_effect=replace_after_read):
            with self.assertRaisesRegex(RuntimeError, 'changed while reading'):
                clients.socks_info()

    def test_publication_change_in_same_container_refuses_stale_access(self):
        def change_after_read(args, data=None, check=True):
            response = self.command(args, data, check)
            if args[:2] == ['docker', 'exec']:
                self.container['NetworkSettings']['Ports']['1080/tcp'][0]['HostPort'] = '2080'
            return response

        with patch.object(clients, 'run', side_effect=change_after_read):
            with self.assertRaisesRegex(RuntimeError, 'changed while reading'):
                clients.socks_info()

    def test_status_identifies_existing_shared_service_without_credentials_or_adoption(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(clients, 'AWG_DIR', Path(folder)), \
                patch.object(clients, 'run', side_effect=self.command), \
                patch.object(clients, 'amnezia_containers', return_value=[]), \
                patch.object(clients, 'shared_awg_status', return_value={}), \
                patch.object(clients, 'vless_manager', return_value=Mock(status=Mock(return_value={}))):
            state = clients.status()
        self.assertEqual(state['socks5_source'], 'amnezia-socks5proxy')
        self.assertEqual(state['socks5_container_id'], 'a' * 64)
        self.assertEqual(state['socks5_port'], 49152)
        self.assertTrue(state['socks5'])
        self.assertFalse(state['socks5_owned'])
        self.assertNotIn('password', state)
        self.assertFalse(any(args[:2] == ['docker', 'exec'] for args in self.commands))

    def test_stopped_service_uses_saved_publication_not_stale_runtime(self):
        self.container['State']['Running'] = False
        self.container['HostConfig']['PortBindings']['1080/tcp'][0]['HostPort'] = '2080'
        self.assertEqual(clients.socks_publications(self.container)['1080/tcp'][0]['HostPort'], '2080')

    def test_stop_during_read_is_not_reported_as_an_unchanged_running_proxy(self):
        self.container['HostConfig']['PortBindings']['1080/tcp'][0]['HostPort'] = '49152'

        def stop_after_read(args, data=None, check=True):
            response = self.command(args, data, check)
            if args[:2] == ['docker', 'exec']:
                self.container['State']['Running'] = False
            return response

        with patch.object(clients, 'run', side_effect=stop_after_read):
            with self.assertRaisesRegex(RuntimeError, 'changed while reading'):
                clients.socks_info()

    def test_unknown_identity_is_not_used_to_fetch_credentials(self):
        self.container['Id'] = 'not-a-container-id'
        with patch.object(clients, 'run', side_effect=self.command):
            with self.assertRaisesRegex(RuntimeError, 'identity could not be verified'):
                clients.socks_info()
        self.assertFalse(any(args[:2] == ['docker', 'exec'] for args in self.commands))


if __name__ == '__main__':
    unittest.main()

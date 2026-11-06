"""External Amnezia protocol inventory is read-only and does not imply ownership."""
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
spec = importlib.util.spec_from_file_location('external_inventory_test', Path(__file__).resolve().parents[1] / 'server/clients.py')
clients = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clients)


def result(text='', code=0):
    return subprocess.CompletedProcess([], code, text, '')


class ExternalInventoryTests(unittest.TestCase):
    def test_official_awg_container_is_a_protocol_not_an_app_or_owned_deployment(self):
        def run(args, data=None, check=True):
            if args[:3] == ['docker', 'container', 'ls']:
                return result('amnezia-awg2\namnezia-awg\namnezia-socks5proxy\nunrelated\n')
            self.assertEqual(args[:4], ['docker', 'inspect', '--type', 'container'])
            return result(json.dumps({'Running': args[-1] == 'amnezia-awg2'}))
        with patch.object(clients, 'run', side_effect=run):
            found = clients.amnezia_containers()
        self.assertEqual([entry['source'] for entry in found], ['amnezia-awg2', 'amnezia-awg'])
        self.assertTrue(all(entry['protocol'] == 'amneziawg' and not entry['owned'] for entry in found))
        self.assertEqual(found[0]['tool'], 'awg')
        self.assertEqual(found[1]['tool'], 'wg')

    def test_external_data_plane_and_generation_are_observed_without_adoption(self):
        source = dict(source='amnezia-awg2', interface='awg0', tool='awg', running=True)
        for go in (False, True):
            def run(args, data=None, check=True):
                if args[-2:] == ['cat', '/opt/amnezia/awg/awg0.conf']:
                    return result('[Interface]\nListenPort = 51820\nS3 = 0\nS4 = 0\n')
                if args[:2] == ['docker', 'top']:
                    return result('PID COMMAND\n42 ' + ('amneziawg-go\n' if go else 'tail\n'))
                return result(json.dumps([{'flags': ['UP'], 'linkinfo': {'info_kind': 'amneziawg'}}]))
            with self.subTest(go=go), patch.object(clients, 'run', side_effect=run), \
                    patch.object(clients, 'container_manager', return_value=Mock(public_port=Mock(return_value=585))):
                observed = clients.external_awg_details(source)
            self.assertEqual(observed['protocol_version'], '2')
            self.assertEqual(observed['port'], 585)
            self.assertEqual(observed['kernel'], not go)
            self.assertEqual(observed['data_plane'], 'userspace' if go else 'kernel')
            self.assertFalse(observed['owned'])

    def test_external_inspection_failure_is_not_reported_as_verified_kernel(self):
        source = dict(source='amnezia-awg2', interface='awg0', tool='awg', running=True)
        with patch.object(clients, 'run', return_value=result('', 1)):
            observed = clients.external_awg_details(source)
        self.assertFalse(observed['kernel'])
        self.assertEqual(observed['data_plane'], 'unknown')
        self.assertIn('error', observed)

    def test_stopped_external_inventory_does_not_start_or_enter_container(self):
        with patch.object(clients, 'run') as run:
            observed = clients.external_awg_details(dict(source='amnezia-awg2', running=False))
        run.assert_not_called()
        self.assertEqual(observed['protocol'], 'amneziawg')

    def test_bad_socks_inspection_does_not_hide_other_services(self):
        with tempfile.TemporaryDirectory() as folder:
            def run(args, data=None, check=True):
                if args[:4] == ['docker', 'inspect', '--type', 'container']:
                    return result('not-json')
                if args[:2] == ['sh', '-c']:
                    return result()
                return result('', 1)
            with patch.object(clients, 'AWG_DIR', Path(folder)), patch.object(clients, 'run', side_effect=run), \
                    patch.object(clients, 'amnezia_containers', return_value=[]), \
                    patch.object(clients, 'shared_awg_status', return_value={}), \
                    patch.object(clients, 'vless_manager', return_value=Mock(status=Mock(return_value={'vless': True}))):
                observed = clients.status()
        self.assertTrue(observed['vless'])
        self.assertIn('socks5_error', observed)
        self.assertIn('ssh_error', observed)

    def test_socks_access_uses_published_host_port_not_container_port(self):
        def run(args, data=None, check=True):
            if args[:2] == ['docker', 'exec']:
                return result('users synthetic:CL:synthetic_placeholder\nsocks -p1080\n')
            return result(json.dumps([{'Id': 'a' * 64, 'HostConfig': {'PortBindings': {
                '1080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '9443'}]}}}]))
        with patch.object(clients, 'run', side_effect=run):
            self.assertEqual(clients.socks_info()['port'], 9443)


if __name__ == '__main__':
    unittest.main()

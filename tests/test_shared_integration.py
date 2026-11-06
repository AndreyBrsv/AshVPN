"""Shared deployment routing uses only isolated state and fake commands."""
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
spec = importlib.util.spec_from_file_location('shared_clients_test', Path(__file__).resolve().parents[1] / 'server/clients.py')
clients = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clients)


class SharedIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        for key, value in {'AWG_DIR': self.root / 'host',
                           'SHARED_AWG_STATE': self.root / 'deployment.json'}.items():
            context = patch.object(clients, key, value)
            context.start(); self.addCleanup(context.stop)
        clients.AWG_DIR.mkdir()
        self.commands = Mock(return_value=subprocess.CompletedProcess([], 1, '', ''))
        context = patch.object(clients, 'run', self.commands)
        context.start(); self.addCleanup(context.stop)
        self.manager = Mock()
        self.manager.status.return_value = {'vless': False}
        for key, value in {'vless_manager': Mock(return_value=self.manager),
                           'amnezia_containers': Mock(return_value=[])}.items():
            context = patch.object(clients, key, value)
            context.start(); self.addCleanup(context.stop)

    def test_unconfigured_host_does_not_load_or_adopt_shared_helper(self):
        with patch.object(clients, 'shared_awg_manager') as helper:
            self.assertEqual(clients.shared_awg_status(), {'configured': False})
            helper.assert_not_called()

    def test_verified_shared_status_is_not_reported_as_host_configuration(self):
        shared = dict(configured=True, running=True, kernel=True, userspace=False,
                      guard_intact=True, port=585)
        with patch.object(clients, 'shared_awg_status', return_value=shared):
            status = clients.status()
        self.assertTrue(status['awg'])
        self.assertTrue(status['kernel'])
        self.assertEqual(status['awg_deployment'], 'amnezia')
        self.assertEqual(status['awg_source'], 'amnezia-awg2')
        self.assertEqual(status['awg_port'], 585)
        self.assertFalse(status['awg_host_configured'])
        self.assertTrue(status['awg_configured'])

    def test_broken_guard_never_reports_a_verified_kernel(self):
        shared = dict(configured=True, running=True, kernel=True, userspace=False,
                      guard_intact=False, error='Kernel guard changed.')
        with patch.object(clients, 'shared_awg_status', return_value=shared):
            status = clients.status()
            with self.assertRaisesRegex(RuntimeError, 'safety checks'):
                clients.client_action('add-client', ['Phone', 'amnezia-awg2', '203.0.113.10', '1.1.1.1'])
        self.assertFalse(status['kernel'])
        self.assertEqual(status['awg_error'], 'Kernel guard changed.')

    def test_owned_shared_service_controls_use_shared_adapter_only(self):
        helper = Mock()
        helper.control.return_value = {'ok': True}
        with patch.object(clients, 'shared_awg_status', return_value={'configured': True}), \
                patch.object(clients, 'shared_awg_manager', return_value=helper):
            self.assertEqual(clients.service_control('awg', 'stop'), {'ok': True})
        backend, operation = helper.control.call_args.args
        self.assertEqual(operation, 'stop')
        self.assertIs(backend.run, self.commands)
        self.commands.assert_not_called()

    def test_uncertain_or_userspace_state_cannot_create_shared_clients(self):
        for drift in ({'error': 'Process inspection failed.'}, {'userspace': True}):
            shared = dict(configured=True, running=True, kernel=True, guard_intact=True,
                          userspace=False, **({'error': drift['error']} if 'error' in drift else {}))
            shared.update(drift)
            with self.subTest(drift=drift), patch.object(clients, 'shared_awg_status', return_value=shared):
                self.assertFalse(clients.status()['kernel'])
                with self.assertRaisesRegex(RuntimeError, 'safety checks'):
                    clients.client_action('add-client', ['Phone', 'amnezia-awg2', '203.0.113.10', '1.1.1.1'])

    def test_conflicting_host_files_prevent_shared_service_changes(self):
        (clients.AWG_DIR / 'awg0.conf').write_text('unrelated host fixture')
        helper = Mock()
        with patch.object(clients, 'shared_awg_status', return_value={'configured': True}), \
                patch.object(clients, 'shared_awg_manager', return_value=helper):
            with self.assertRaisesRegex(ValueError, 'Conflicting'):
                clients.service_control('awg', 'restart')
        helper.control.assert_not_called()
        self.commands.assert_not_called()


if __name__ == '__main__':
    unittest.main()

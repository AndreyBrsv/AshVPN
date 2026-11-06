"""Lifecycle tests use isolated files and fake modules; never mutate a VPS."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
with patch.dict(sys.modules, {'fcntl': SimpleNamespace()} if os.name == 'nt' else {}):
    spec = importlib.util.spec_from_file_location('lifecycle', ROOT / 'server/lifecycle.py')
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # macOS exposes TMPDIR through /var, a system symlink to /private/var.
        # Canonicalize the fixture, keeping production link rejection intact.
        self.root = Path(temporary.name).resolve()
        self.security_state = self.root / 'security'; self.security_state.mkdir()
        self.server = {'awg': False, 'kernel': False, 'userspace': False, 'socks5': False,
                       'ssh': {'permitrootlogin': 'prohibit-password', 'passwordauthentication': 'yes'},
                       'icmp_blocked': False}
        self.security = {'ssh': self.server['ssh'], 'fail2ban': {'managed': False, 'enabled': False},
                         'firewall': {'managed': False, 'enabled': False},
                         'automatic_updates': {'managed': False, 'enabled': False}, 'warnings': []}
        self.rows = []
        self.clients = SimpleNamespace(status=lambda: self.server, socks_check=lambda: {'ok': True},
                                       list_clients=lambda: {'clients': self.rows})
        self.security_module = SimpleNamespace(STATE=self.security_state, capture_baseline=lambda: None,
                                               diagnostics=lambda: self.security, effective_ssh=lambda: self.server['ssh'],
                                               prepare_legacy_ssh=Mock(), record_legacy_ssh=Mock())
        self.modules = {'security_manager': self.security_module, 'clients': self.clients}
        for key, value in {'STATE': self.root / 'lifecycle', 'LOCK': self.root / 'lock',
                           'CLIENT_LOCK': self.root / 'client-lock',
                           'AWG': self.root / 'awg', 'FORWARDING': self.root / 'forwarding.conf',
                           'PING': self.root / 'ping', 'SOCKS_DIRECTORY': self.root / 'socks'}.items():
            mock = patch.object(lifecycle, key, value)
            mock.start(); self.addCleanup(mock.stop)
        for mock in (patch.object(lifecycle, 'module', side_effect=lambda name: self.modules[name]),
                     patch.object(lifecycle.shutil, 'which', return_value=None),
                     patch.object(lifecycle, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr=''))):
            mock.start(); self.addCleanup(mock.stop)
        if os.name == 'nt':
            mock = patch.object(lifecycle, 'fcntl', SimpleNamespace(flock=lambda *_: None, LOCK_EX=1, LOCK_NB=2))
            mock.start(); self.addCleanup(mock.stop)

    def begin(self, **desired):
        return lifecycle.begin({'desired': desired, 'steps': ['dependencies', 'inspect', 'verify']})

    def test_rejects_secret_fields_before_any_state_write(self):
        for key in ('password', 'user', 'client_names', 'admin_name', 'private_key', 'credentials_ref'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'non-secret'):
                self.begin(**{key: 'not-written'})
        self.assertFalse((lifecycle.STATE / 'state.json').exists())

    def test_explicit_resume_preserves_completed_steps_but_rejects_changed_answers(self):
        started = self.begin(install_awg=True, awg_port=585)
        lifecycle.step(started['run_id'], 'dependencies', 'done')
        lifecycle.step(started['run_id'], 'inspect', 'failed')
        request = {'desired': started['desired'], 'steps': ['dependencies', 'inspect', 'verify'],
                   'resume': True, 'run_id': started['run_id']}
        resumed = lifecycle.begin(request)
        self.assertEqual(resumed['run_id'], started['run_id'])
        self.assertEqual(resumed['steps']['dependencies']['state'], 'done')
        request['desired'] = {'install_awg': True, 'awg_port': 586}
        with self.assertRaisesRegex(ValueError, 'changed'):
            lifecycle.begin(request)

    def test_completion_requires_every_selected_step_and_rejects_stale_run(self):
        started = self.begin(install_awg=False)
        with self.assertRaises(ValueError): lifecycle.finish(started['run_id'], 'complete')
        for identity in started['steps']:
            lifecycle.step(started['run_id'], identity, 'done')
        self.assertEqual(lifecycle.finish(started['run_id'], 'complete')['status'], 'complete')
        with self.assertRaises(ValueError): lifecycle.step('stale', 'verify', 'done')

    def test_journal_is_bounded_and_does_not_store_arbitrary_output(self):
        state = lifecycle.load()
        for index in range(200): lifecycle.event(state, 'icmp', 'done')
        lifecycle.save(state)
        self.assertEqual(len(lifecycle.load()['events']), 160)
        lifecycle.record_action('not-a-real-action', 'failed')
        self.assertEqual(len(lifecycle.load()['events']), 160)

    def test_credential_commit_evidence_survives_failed_step_and_explicit_resume(self):
        started = lifecycle.begin({'desired': {'create_admin': True}, 'steps': ['administrator', 'verify']})
        run = started['run_id']
        lifecycle.step(run, 'administrator', 'running')
        lifecycle.record_credential('administrator', 'started')
        self.assertEqual(lifecycle.load()['steps']['administrator']['credential_state'], 'started')
        lifecycle.record_credential('administrator', 'committed')
        lifecycle.step(run, 'administrator', 'failed')
        self.assertEqual(lifecycle.load()['steps']['administrator']['credential_state'], 'committed')
        lifecycle.begin({'desired': started['desired'], 'steps': list(started['steps']), 'run_id': run, 'resume': True})
        lifecycle.step(run, 'administrator', 'running')
        lifecycle.record_credential('administrator', 'started')
        lifecycle.step(run, 'administrator', 'done')
        self.assertEqual(lifecycle.status()['steps']['administrator']['credential_state'], 'committed')

    def test_credential_markers_reject_arbitrary_fields_and_ignore_inactive_manual_actions(self):
        lifecycle.record_credential('administrator', 'started')
        self.assertFalse((lifecycle.STATE / 'state.json').exists())
        started = lifecycle.begin({'desired': {'change_root_password': True}, 'steps': ['root-password', 'verify']})
        before = (lifecycle.STATE / 'state.json').read_bytes()
        lifecycle.record_credential('root-password', 'started')
        lifecycle.record_credential('administrator', 'started')
        self.assertEqual((lifecycle.STATE / 'state.json').read_bytes(), before)
        for step_id, outcome in [('username', 'started'), ('root-password', 'synthetic_secret'),
                                 ('synthetic_secret', 'committed')]:
            with self.subTest(step=step_id), self.assertRaisesRegex(ValueError, 'Invalid credential progress'):
                lifecycle.record_credential(step_id, outcome)
        lifecycle.step(started['run_id'], 'root-password', 'running')
        with self.assertRaisesRegex(ValueError, 'no matching start'):
            lifecycle.record_credential('root-password', 'committed')
        lifecycle.record_credential('root-password', 'started')
        lifecycle.record_credential('root-password', 'committed')
        lifecycle.step(started['run_id'], 'root-password', 'failed')
        before = (lifecycle.STATE / 'state.json').read_bytes()
        lifecycle.record_credential('root-password', 'started')
        self.assertEqual((lifecycle.STATE / 'state.json').read_bytes(), before)
        self.assertNotIn('synthetic_secret', before.decode())

    def test_legacy_ssh_requires_preparation_before_the_action_can_mutate(self):
        lifecycle.record_action('ssh-config', 'running')
        self.security_module.prepare_legacy_ssh.assert_called_once_with()
        self.security_module.record_legacy_ssh.assert_not_called()
        lifecycle.record_action('ssh-config', 'done')
        self.security_module.record_legacy_ssh.assert_called_once_with()
        self.security_module.prepare_legacy_ssh.side_effect = ValueError('Synthetic ownership drift')
        before = (lifecycle.STATE / 'state.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'ownership drift'):
            lifecycle.record_action('ssh-config', 'running')
        self.assertEqual((lifecycle.STATE / 'state.json').read_bytes(), before)

    def test_diagnostics_compares_selected_ports_and_authentication(self):
        self.begin(install_awg=True, awg_port=585, awg_client_count=1,
                   install_socks=True, socks_port=1080, socks_access='private', disable_root=True)
        self.server.update(awg=True, kernel=True, awg_configured=True, awg_port=9999,
                           interface='awg0', socks5=True, socks5_configured=True, socks5_port=1080,
                           socks5_access='public')
        self.clients.socks_check = lambda: (_ for _ in ()).throw(RuntimeError('password should never be printed'))
        self.rows = [{'source': 'amnezia-awg2', 'name': 'foreign'}]
        result = lifecycle.diagnostics()
        failures = {item['id'] for item in result['checks'] if item['status'] == 'fail'}
        self.assertTrue({'awg-port', 'socks5', 'socks5-access', 'root-login', 'awg_client_count'} <= failures)
        self.assertNotIn('password should', json.dumps(result))
        self.assertFalse(result['healthy'])
        self.assertEqual(next(item for item in result['checks'] if item['id'] == 'external-connectivity')['required'], False)

    def test_diagnostics_keeps_other_results_when_service_inspection_fails(self):
        self.begin(protect_ssh=True)
        self.clients.status = lambda: (_ for _ in ()).throw(ValueError('private config'))
        result = lifecycle.diagnostics()
        self.assertEqual(next(c for c in result['checks'] if c['id'] == 'services')['status'], 'fail')
        self.assertEqual(next(c for c in result['checks'] if c['id'] == 'fail2ban')['status'], 'fail')
        self.assertIn('security', result['actual'])
        self.assertNotIn('private config', json.dumps(result))

    def test_external_automatic_updates_are_preserved_when_app_setting_is_off(self):
        self.begin(automatic_updates=False)
        self.security['automatic_updates'].update(managed=False, enabled=True)
        self.assertTrue(lifecycle.diagnostics()['healthy'])

    def test_external_only_awg_does_not_require_an_unselected_managed_kernel_service(self):
        self.begin(install_awg=False)
        self.server.update(awg_configured=True, awg_host_configured=False,
                           external_awg=[{'source': 'amnezia-awg2', 'running': True,
                                          'kernel': True, 'data_plane': 'kernel', 'owned': False}])
        result = lifecycle.diagnostics()
        self.assertTrue(result['healthy'])
        self.assertFalse(any(row['id'] in ('awg', 'awg-port', 'awg-routing', 'awg-forwarding')
                             for row in result['checks']))
        external = next(row for row in result['checks'] if row['id'] == 'external-awg-amnezia-awg2')
        self.assertEqual(external['status'], 'pass')
        self.assertFalse(external['required'])

    def test_external_userspace_stopped_or_uncertain_service_remains_an_explicit_warning(self):
        self.begin(install_awg=False)
        for state in ({'running': True, 'userspace': True, 'data_plane': 'userspace'},
                      {'running': False}, {'running': True, 'error': 'private error not echoed'},
                      {'running': True, 'data_plane': 'unknown'}):
            self.server.update(awg_configured=True, awg_host_configured=False, userspace=True,
                               external_awg=[{'source': 'amnezia-awg2', **state}])
            result = lifecycle.diagnostics()
            self.assertTrue(result['healthy'])
            external = next(row for row in result['checks'] if row['id'] == 'external-awg-amnezia-awg2')
            self.assertEqual(external['status'], 'warn')
            self.assertFalse(external['required'])
            self.assertNotIn('private error', external['detail'])

    def test_external_healthy_service_cannot_satisfy_selected_managed_awg_requirement(self):
        self.begin(install_awg=True, awg_port=585, awg_deployment='host')
        self.server.update(awg_configured=True, awg_host_configured=False,
                           external_awg=[{'source': 'amnezia-awg2', 'running': True, 'kernel': True}])
        result = lifecycle.diagnostics()
        self.assertFalse(result['healthy'])
        self.assertEqual(next(row for row in result['checks'] if row['id'] == 'awg')['status'], 'fail')

    def test_managed_awg_drift_and_global_discovery_failures_still_fail_closed(self):
        self.begin(install_awg=False)
        for state in ({'awg_host_configured': True, 'awg_error': 'unreadable'},
                      {'awg_deployment': 'amnezia', 'awg_error': 'invalid guard'}):
            baseline = dict(self.server)
            self.server.update(state)
            result = lifecycle.diagnostics()
            self.assertFalse(result['healthy'])
            self.server.clear(); self.server.update(baseline)

    def test_unknown_external_discovery_warns_unrelated_setup_but_blocks_new_network_services(self):
        self.begin(install_awg=False)
        self.server['vpn_detection_error'] = 'unavailable'
        result = lifecycle.diagnostics()
        self.assertTrue(result['healthy'])
        self.assertEqual(next(row for row in result['checks'] if row['id'] == 'vpn-discovery')['status'], 'warn')
        self.begin(install_awg=False, install_vless=True)
        result = lifecycle.diagnostics()
        self.assertFalse(result['healthy'])
        self.assertEqual(next(row for row in result['checks'] if row['id'] == 'vpn-discovery')['status'], 'fail')

    def test_untracked_components_are_not_removable(self):
        lifecycle.AWG.mkdir()
        (lifecycle.AWG / 'params').write_text('external')
        plan = lifecycle.reset_preview()
        self.assertFalse(next(row for row in plan['components'] if row['id'] == 'host')['removable'])
        self.assertEqual(lifecycle.reset(plan['digest'])['removed'], [])
        self.assertTrue((lifecycle.AWG / 'params').exists())

    def test_owned_ping_removal_refuses_changed_file_after_preview(self):
        lifecycle.record_action('icmp', 'running')
        lifecycle.PING.write_text('# ashapp-owned-icmp-v1\n')
        lifecycle.record_action('icmp', 'done')
        plan = lifecycle.reset_preview()
        self.assertTrue(plan['components'][0]['removable'])
        lifecycle.PING.write_text('external edit')
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            lifecycle.reset(plan['digest'])
        self.assertEqual(lifecycle.PING.read_text(), 'external edit')

    def test_ping_marker_does_not_authorize_edited_script(self):
        source = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')
        expected = source.split("cat > /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp <<'PLUGIN'\n", 1)[1].split('\nPLUGIN\n', 1)[0] + '\n'
        lifecycle.PING.write_text(expected)
        self.assertTrue(lifecycle.verify_ping()['verified'])
        lifecycle.PING.write_text(expected + '# external edit\n')
        with self.assertRaisesRegex(ValueError, 'not executed'):
            lifecycle.verify_ping()

    def test_ledger_symlink_is_rejected(self):
        target = self.root / 'elsewhere'; target.write_text('unchanged')
        lifecycle.STATE.mkdir()
        try:
            (lifecycle.STATE / 'state.json').symlink_to(target)
        except OSError:
            self.skipTest('Symlink creation is unavailable.')
        with self.assertRaises(ValueError): lifecycle.load()
        self.assertEqual(target.read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main()

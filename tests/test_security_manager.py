"""Exercise security planning/recovery with fake commands and isolated files only."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.dict(sys.modules, {'fcntl': SimpleNamespace()} if os.name == 'nt' else {}):
    spec = importlib.util.spec_from_file_location('security_manager', ROOT / 'server/security_manager.py')
    security = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(security)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = {key: self.root / (key + '.conf') for key in security.FILES}
        self.state = self.root / 'state'; self.state.mkdir()
        self.main = self.root / 'sshd_config'; self.main.write_text('Port 2222\nPasswordAuthentication yes\n')
        self.plugin = self.root / 'plugin'
        self.commands = []
        self.chains = {}
        self.banned = set()
        self.ssh_connection = patch.dict(os.environ, {'SSH_CONNECTION': '198.51.100.10 30000 203.0.113.10 2222'})
        self.ssh_connection.start(); self.addCleanup(self.ssh_connection.stop)
        for key, value in {'FILES': self.files, 'STATE': self.state, 'SSH_MAIN': self.main,
                           'HELPER': self.root / 'helper.py', 'PLUGIN': self.plugin,
                           'RECOVERY': self.root / 'recovery.service',
                           'LEGACY_SSH': self.root / 'legacy-ssh.conf',
                           'AWG_DIRECTORY': self.root / 'awg', 'VLESS_STATE': self.root / 'vless-state.json',
                           'DOCKER_DROPIN': self.root / 'docker-dropin.conf'}.items():
            context = patch.object(security, key, value)
            context.start(); self.addCleanup(context.stop)
        for context in (patch.object(security, 'run', self.fake_run), patch.object(security.shutil, 'which', return_value=None)):
            context.start(); self.addCleanup(context.stop)

    def fake_run(self, args, check=True, data=None):
        self.commands.append(args)
        code, output = 0, ''
        if args == ['/usr/sbin/sshd', '-T']:
            values = {'permitrootlogin': 'prohibit-password', 'passwordauthentication': 'yes',
                      'kbdinteractiveauthentication': 'yes', 'pubkeyauthentication': 'yes'}
            if self.files['ssh'].exists():
                values.update((key.lower(), value) for key, value in
                              (line.split(None, 1) for line in self.files['ssh'].read_text().splitlines()))
            output = 'port 2222\n' + ''.join(f'{key} {value}\n' for key, value in values.items())
        elif args[:3] == ['ss', '-H', '-lntu']:
            output = ('tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n'
                      'tcp LISTEN 0 128 [::]:443 [::]:*\n'
                      'tcp LISTEN 0 128 127.0.0.1:1080 0.0.0.0:*\n'
                      'udp UNCONN 0 0 0.0.0.0:585 0.0.0.0:*\n')
        elif args[:2] == ['systemctl', 'is-active']:
            code = 1
        elif args[:2] == ['systemctl', 'is-enabled']:
            code, output = 1, 'disabled\n'
        elif args[:3] == ['fail2ban-client', 'get', 'ashapp-sshd']:
            output = {'maxretry': '5', 'findtime': '600', 'bantime': '900', 'journalmatch': '_COMM=sshd',
                      'banip': ' '.join(self.banned)}.get(args[3], '')
        elif args[:3] == ['fail2ban-client', 'set', 'ashapp-sshd']:
            if args[3] == 'banip': self.banned.add(args[4])
            else: self.banned.discard(args[4])
        elif args[0] in ('iptables-restore', 'ip6tables-restore'):
            tool = args[0].removesuffix('-restore')
            for line in data.splitlines():
                if line.startswith(':'): self.chains.setdefault((tool, line.split()[0][1:]), [])
                elif line.startswith('-'): self.fake_run([tool, *line.split()])
        elif args[0] in ('iptables', 'ip6tables'):
            tool, operation, chain = args[:3]
            key = (tool, chain)
            if operation == '-S':
                code = 0 if chain == 'INPUT' or key in self.chains else 1
                if chain == 'INPUT': output = '-P INPUT ACCEPT\n'
                output += ''.join('-A ' + chain + ' ' + ' '.join(rule) + '\n' for rule in self.chains.get(key, []))
            if operation == '-S' and chain == 'f2b-ashapp-sshd':
                code = 0
                output = ''.join(f'-A {chain} -s {address} -j REJECT\n' for address in self.banned)
            elif operation == '-N': self.chains[key] = []
            elif operation == '-F': self.chains[key] = []
            elif operation == '-X': self.chains.pop(key)
            elif operation == '-A': self.chains.setdefault(key, []).append(args[3:])
            elif operation == '-C': code = 0 if args[3:] in self.chains.get(key, []) else 1
            elif operation == '-D': self.chains[key].remove(args[3:])
            elif operation == '-I': self.chains.setdefault(key, []).insert(int(args[3]) - 1, args[4:])
        if check and code: raise RuntimeError('Simulated command failure.')
        return SimpleNamespace(returncode=code, stdout=output, stderr='')

    def stage(self, changes):
        preview = security.preview(changes)
        return security.stage(changes, preview['digest'])

    def confirm(self, token):
        with patch.dict(os.environ, {'SSH_CONNECTION': '198.51.100.10 30001 203.0.113.10 2222'}):
            return security.confirm(token)

    def test_preview_is_read_only_and_keeps_actual_ssh_and_existing_public_services(self):
        plan = security.preview({'firewall': True})
        self.assertEqual(plan['ports'], {'tcp': [443, 2222], 'udp': [585]})
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertFalse(any('-A' in command or '-F' in command for command in self.commands))

    def test_listener_interface_suffixes_preserve_dhcp_but_exclude_loopback(self):
        def scoped_run(args, check=True, data=None):
            if args[:3] == ['ss', '-H', '-lntu']:
                return SimpleNamespace(returncode=0, stderr='', stdout=(
                    'udp UNCONN 0 0 203.0.113.10%ens3:68 0.0.0.0:*\n'
                    'udp UNCONN 0 0 [fe80::1%ens3]:546 [::]:*\n'
                    'tcp LISTEN 0 128 127.0.0.53%lo:53 0.0.0.0:*\n'
                    'tcp LISTEN 0 128 [::1%lo]:1080 [::]:*\n'))
            return self.fake_run(args, check, data)

        with patch.object(security, 'run', scoped_run):
            self.assertEqual(security.listeners(), {'tcp': [], 'udp': [68, 546]})

    def test_dhcp_rebinding_during_dependency_install_does_not_invalidate_review(self):
        state = {'installed': False}

        def rebind_run(args, check=True, data=None):
            if args[0] == 'apt-get' and 'install' in args:
                state['installed'] = True
            if args[:3] == ['ss', '-H', '-lntu']:
                host = '0.0.0.0' if state['installed'] else '203.0.113.10%ens3'
                return SimpleNamespace(returncode=0, stderr='', stdout=f'udp UNCONN 0 0 {host}:68 0.0.0.0:*\n')
            return self.fake_run(args, check, data)

        with patch.object(security, 'run', rebind_run):
            before = security.preview({'fail2ban': True})
            self.assertEqual(before['ports']['udp'], [68])
            staged = security.stage({'fail2ban': True}, before['digest'])
            self.assertTrue(self.confirm(staged['token'])['confirmed'])

    def test_rejects_unknown_or_non_boolean_switches(self):
        for changes in ({}, {'firewall': 1}, {'command': 'whoami'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                security.preview(changes)

    def test_ssh_include_match_is_rejected_before_mutation(self):
        included = self.root / 'conditional.conf'
        included.write_text('Match Address 198.51.100.10\n PermitRootLogin yes\n')
        # Production parses Linux paths. Windows runner temp paths can contain
        # short-name tildes, which are intentionally unsupported Include syntax.
        self.main.write_text('Include /etc/ssh/conditional-test.conf\n')
        with patch('glob.glob', return_value=[str(included)]):
            with self.assertRaisesRegex(ValueError, 'Conditional'):
                security.preview({'disable_root': True})
        self.assertEqual(list(self.state.iterdir()), [])

    def test_stale_preview_and_foreign_owned_path_are_refused(self):
        plan = security.preview({'firewall': True})
        self.main.write_text('PasswordAuthentication no\n')
        with self.assertRaisesRegex(ValueError, 'changed after preview'):
            security.stage({'firewall': True}, plan['digest'])
        self.files['firewall'].write_text('external')
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            security.preview({'firewall': True})

    def test_dependency_drift_reports_only_changed_categories_and_preserves_guard(self):
        plan = security.preview({'fail2ban': True})

        def changing_run(args, check=True, data=None):
            if args[0] == 'apt-get' and 'install' in args:
                self.main.write_text('Port 2222\n# external-change-fixture\n')
            return self.fake_run(args, check, data)

        with patch.object(security, 'run', changing_run):
            with self.assertRaisesRegex(ValueError, r'dependencies \(files\)') as failure:
                security.stage({'fail2ban': True}, plan['digest'])
        self.assertNotIn('external-change-fixture', str(failure.exception))
        self.assertFalse(security.HELPER.exists())
        self.assertFalse((self.state / 'pending.json').exists())

    def test_ssh_policy_can_only_be_committed_from_a_fresh_connection(self):
        staged = self.stage({'disable_passwords': True})
        self.assertEqual(security.effective_ssh()['passwordauthentication'], 'no')
        with self.assertRaisesRegex(ValueError, 'fresh SSH'):
            security.confirm(staged['token'])
        self.assertTrue(self.confirm(staged['token'])['confirmed'])
        self.assertFalse((self.state / 'pending.json').exists())
        self.assertIn(['systemctl', 'enable', 'ashapp-security-recovery.service'], self.commands)

    def test_rollback_restores_original_policy_and_permissions_without_touching_other_files(self):
        original = self.main.read_bytes()
        self.main.chmod(0o640)
        staged = self.stage({'disable_passwords': True})
        unrelated = self.root / 'unrelated'; unrelated.write_text('keep')
        self.assertTrue(security.rollback(staged['token'])['rolled_back'])
        self.assertEqual(self.main.read_bytes(), original)
        if os.name != 'nt': self.assertEqual(self.main.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.files['ssh'].exists())
        self.assertEqual(unrelated.read_text(), 'keep')

    def test_expired_change_is_not_confirmed_and_recovery_refuses_concurrent_edits(self):
        staged = self.stage({'disable_root': True})
        with patch.object(security.time, 'time', return_value=10**12), self.assertRaisesRegex(ValueError, 'expired'):
            self.confirm(staged['token'])
        self.main.write_text('external edit')
        with self.assertRaisesRegex(ValueError, 'manual review'):
            security.rollback(staged['token'])
        self.assertTrue((self.state / 'pending.json').exists())
        self.assertEqual(self.main.read_text(), 'external edit')

    def test_firewall_disable_removes_only_owned_chains_and_keeps_foreign_policy(self):
        self.chains['iptables', 'INPUT'] = [['-p', 'tcp', '--dport', '8443', '-j', 'ACCEPT']]
        staged = self.stage({'firewall': True}); self.confirm(staged['token'])
        self.assertTrue(self.plugin.exists())
        staged = self.stage({'firewall': False}); self.confirm(staged['token'])
        self.assertEqual(self.chains['iptables', 'INPUT'], [['-p', 'tcp', '--dport', '8443', '-j', 'ACCEPT']])
        self.assertFalse(self.plugin.exists())
        self.assertFalse(any(command[1:3] in (['-F', 'INPUT'], ['-P', 'INPUT']) for command in self.commands))

    def test_docker_native_backend_is_refused_instead_of_claiming_protection(self):
        with patch.object(security, 'docker_ports', return_value=[{'protocol': 'tcp', 'port': 1080}]):
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                security.preview({'firewall': True})

    def test_existing_default_deny_policy_is_never_widened_for_other_listeners(self):
        def restricted(args, check=True, data=None):
            if args == ['iptables', '-S', 'INPUT']:
                return SimpleNamespace(returncode=0, stdout='-P INPUT DROP\n-A INPUT -s 198.51.100.10 -p tcp --dport 2222 -j ACCEPT\n')
            return self.fake_run(args, check, data)
        with patch.object(security, 'run', restricted), self.assertRaisesRegex(ValueError, 'will not be widened'):
            security.preview({'firewall': True})
        self.assertEqual(list(self.state.iterdir()), [])

    def test_partial_replace_is_recoverable_on_either_side_of_atomic_write(self):
        staged = self.stage({'disable_passwords': True})
        pending_path = self.state / 'pending.json'
        pending = json.loads(pending_path.read_text())
        own_path = str(self.files['ssh'])
        pending['expected'][own_path].insert(0, None)
        pending_path.write_text(json.dumps(pending))
        self.files['ssh'].unlink()
        self.assertTrue(security.rollback(staged['token'])['rolled_back'])
        self.assertFalse(self.files['ssh'].exists())

    def test_fail2ban_probes_actions_without_generating_failed_logins_or_changing_prior_bans(self):
        self.banned.add('203.0.113.50')
        security.verify_fail2ban()
        self.assertEqual(self.banned, {'203.0.113.50'})
        self.assertTrue(any(command[:3] == ['fail2ban-client', 'set', 'ashapp-sshd'] for command in self.commands))

    def test_selected_fail2ban_persists_boot_and_rollback_restores_prior_unit_state(self):
        for running in (False, True):
            for enabled in ('disabled', 'enabled'):
                for commit in (False, True):
                    with self.subTest(running=running, enabled=enabled, commit=commit):
                        state = {'active': running, 'enabled': enabled}
                        self.commands.clear()

                        def unit_run(args, check=True, data=None):
                            if args[:2] == ['systemctl', 'is-enabled'] and args[-1].removesuffix('.service') == 'fail2ban':
                                self.commands.append(args)
                                return SimpleNamespace(returncode=0 if state['enabled'] == 'enabled' else 1,
                                                       stdout=state['enabled'] + '\n', stderr='')
                            if args[0] == 'systemctl' and args[-1].removesuffix('.service') == 'fail2ban':
                                if args[1] == 'enable':
                                    state['enabled'] = 'enabled'
                                    if '--now' in args: state['active'] = True
                                elif args[1] == 'disable': state['enabled'] = 'disabled'
                                elif args[1] == 'stop': state['active'] = False
                                elif args[1] == 'start': state['active'] = True
                            return self.fake_run(args, check, data)

                        with patch.object(security, 'run', unit_run), \
                                patch.object(security, 'active', side_effect=lambda unit: state['active'] if unit.removesuffix('.service') == 'fail2ban' else False), \
                                patch.object(security.shutil, 'which', side_effect=lambda name: '/usr/bin/fail2ban-client' if name == 'fail2ban-client' else None):
                            staged = self.stage({'fail2ban': True})
                            self.assertEqual(state, {'active': True, 'enabled': 'enabled'})
                            self.assertEqual(['fail2ban-client', 'reload'] in self.commands, running)
                            if commit:
                                self.assertTrue(self.confirm(staged['token'])['confirmed'])
                                self.assertEqual(state, {'active': True, 'enabled': 'enabled'})
                            else:
                                self.assertTrue(security.rollback(staged['token'])['rolled_back'])
                                self.assertEqual(state, {'active': running, 'enabled': enabled})

    def test_fail2ban_reload_without_start_preserves_shared_service_lifecycle(self):
        for running in (False, True):
            self.commands.clear()
            with patch.object(security, 'active', return_value=running), \
                    patch.object(security.shutil, 'which', return_value='/usr/bin/fail2ban-client'):
                security.reload_fail2ban()
            self.assertEqual(['fail2ban-client', 'reload'] in self.commands, running)
            self.assertFalse(any(command[0] == 'systemctl' for command in self.commands))

    def test_nonstandard_fail2ban_boot_policy_is_refused_without_unmasking_or_conversion(self):
        for boot in ('masked', 'enabled-runtime'):
            with self.subTest(boot=boot):
                self.commands.clear()

                def unit_run(args, check=True, data=None):
                    if args[:2] == ['systemctl', 'is-enabled']:
                        self.commands.append(args)
                        return SimpleNamespace(returncode=0 if boot == 'enabled-runtime' else 1, stdout=boot + '\n', stderr='')
                    return self.fake_run(args, check, data)

                with patch.object(security, 'run', unit_run), \
                        patch.object(security, 'active', side_effect=lambda unit: unit.removesuffix('.service') == 'fail2ban'), \
                        patch.object(security.shutil, 'which', side_effect=lambda name: '/usr/bin/fail2ban-client' if name == 'fail2ban-client' else None):
                    with self.assertRaisesRegex(ValueError, 'startup policy'):
                        self.stage({'fail2ban': True})
                self.assertFalse((self.state / 'pending.json').exists())
                self.assertFalse(self.files['fail2ban'].exists())
                self.assertFalse(any(command[0] == 'systemctl' and command[1] in ('enable', 'disable', 'unmask')
                                     and command[-1].removesuffix('.service') == 'fail2ban' for command in self.commands))

    def test_update_origins_follow_debian_codename_not_moving_suite(self):
        text = security.security_update_text('debian', 'bookworm')
        self.assertIn('origin=Debian,codename=bookworm-security,label=Debian-Security', text)
        self.assertIn('Automatic-Reboot "false"', text)
        self.assertIn('#clear Unattended-Upgrade::Allowed-Origins', text)
        self.assertNotIn('Debian-Security:bookworm-security', text)
        self.assertIn('origin=Ubuntu,archive=noble-security', security.security_update_text('ubuntu', 'noble'))
        with self.assertRaises(ValueError): security.security_update_text('ubuntu', 'noble";evil')

    def test_edited_or_foreign_persistence_files_are_never_overwritten(self):
        staged = self.stage({'firewall': True}); self.confirm(staged['token'])
        for path in (security.PLUGIN, security.HELPER, security.RECOVERY, security.DOCKER_DROPIN):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_text('external administrative edit')
                with self.assertRaisesRegex(ValueError, 'edited outside'):
                    security.preview({'firewall': False})
                self.assertEqual(path.read_text(), 'external administrative edit')
                path.write_bytes(original)

    def test_unknown_persistence_collision_requires_manual_review(self):
        security.RECOVERY.write_text('existing external unit')
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            security.preview({'firewall': True})
        self.assertEqual(security.RECOVERY.read_text(), 'existing external unit')

    def test_firewall_diagnostics_detect_flushed_or_widened_owned_chains(self):
        staged = self.stage({'firewall': True}); self.confirm(staged['token'])
        config = security.read_json(self.files['firewall'])
        self.assertTrue(security.firewall_status(config, [])['enabled'])
        original = list(self.chains['iptables', 'ASHAPP-IN'])
        self.chains['iptables', 'ASHAPP-IN'] = []
        self.assertFalse(security.firewall_status(config, [])['enabled'])
        self.chains['iptables', 'ASHAPP-IN'] = [['-j', 'ACCEPT'], *original]
        self.assertFalse(security.firewall_status(config, [])['enabled'])

    def test_docker_startup_hook_restores_rules_after_early_boot_and_diagnostics_detects_gap(self):
        ports = [{'protocol': 'tcp', 'port': 1080}]
        self.chains['iptables', 'DOCKER-USER'] = []
        with patch.object(security, 'docker_ports', return_value=ports):
            staged = self.stage({'firewall': True}); self.confirm(staged['token'])
        self.assertIn('ExecStartPost=/usr/bin/python3 /opt/ashapp/security_manager.py firewall-restore', security.DOCKER_DROPIN.read_text())
        config = security.read_json(self.files['firewall'])
        self.chains.clear()  # netfilter-persistent runs before Docker creates its hook
        security.firewall_reconcile()
        self.assertTrue(security.firewall_status(config, [])['host_verified'])
        self.assertFalse(security.firewall_status(config, [])['enabled'])
        self.chains['iptables', 'DOCKER-USER'] = []  # Docker is now ready
        security.check_owned(allow_pending=True)
        security.firewall_reconcile()  # same action as ExecStartPost
        self.assertTrue(security.firewall_status(config, ports)['enabled'])
        saved = list(self.chains['iptables', 'ASHAPP-DKR'])
        self.chains['iptables', 'ASHAPP-DKR'] = []
        self.assertFalse(security.firewall_status(config, ports)['enabled'])
        self.chains['iptables', 'ASHAPP-DKR'] = saved
        self.assertFalse(security.firewall_status(config, ports + [{'protocol': 'tcp', 'port': 1081}])['enabled'])
        staged = self.stage({'firewall': False}); self.confirm(staged['token'])
        self.assertFalse(security.DOCKER_DROPIN.exists())

    def test_reset_restores_earliest_ssh_baseline_and_requires_independent_confirmation(self):
        original = self.main.read_text()
        staged = self.stage({'disable_root': True, 'firewall': True})
        self.confirm(staged['token'])
        plan = security.reset_preview()
        self.assertTrue(plan['available'])
        staged_reset = security.reset_stage(plan['digest'])
        self.assertEqual(self.main.read_text(), original)
        self.assertFalse(self.files['firewall'].exists())
        with self.assertRaisesRegex(ValueError, 'fresh SSH'):
            security.confirm(staged_reset['token'])
        self.assertTrue(self.confirm(staged_reset['token'])['confirmed'])
        self.assertEqual(security.owned(), {})
        self.assertFalse(security.HELPER.exists())

    def test_reset_does_not_discard_externally_edited_ssh_configuration(self):
        staged = self.stage({'disable_root': True}); self.confirm(staged['token'])
        self.main.write_text(self.main.read_text() + '# outside edit\n')
        with self.assertRaisesRegex(ValueError, 'outside Ashapp'):
            security.reset_preview()

    def test_firewall_confirmation_does_not_launder_external_main_or_legacy_ssh_edits(self):
        for path in (self.main, security.LEGACY_SSH):
            with self.subTest(path=path.name):
                staged = self.stage({'firewall': True}); self.confirm(staged['token'])
                tracked = security.read_json(self.state / 'baseline.json')['expected'].copy()
                original = path.read_bytes() if path.exists() else None
                path.write_text((original.decode() if original else '') + '# outside administrative edit\n')
                with self.assertRaisesRegex(ValueError, 'outside Ashapp'):
                    security.reset_preview()
                staged = self.stage({'firewall': False}); self.confirm(staged['token'])
                self.assertEqual(security.read_json(self.state / 'baseline.json')['expected'], tracked)
                with self.assertRaisesRegex(ValueError, 'outside Ashapp'):
                    security.reset_preview()
                self.assertIn('outside administrative edit', path.read_text())
                if original is None: path.unlink()
                else: path.write_bytes(original)

    def test_new_ssh_stage_refuses_external_edits_before_any_mutation(self):
        security.capture_baseline()
        self.main.write_text(self.main.read_text() + '# outside edit\n')
        before_commands = len(self.commands)
        with self.assertRaisesRegex(ValueError, 'outside Ashapp'):
            security.preview({'disable_root': True})
        self.assertFalse(self.files['ssh'].exists())
        self.assertFalse((self.state / 'pending.json').exists())
        self.assertFalse(any(command[0] == 'systemd-run' for command in self.commands[before_commands:]))

    def test_confirmation_failure_recovers_ssh_tracking_with_the_staged_files(self):
        staged = self.stage({'disable_root': True})
        before = security.read_json(self.state / 'baseline.json')['expected'].copy()

        def fail_timer_stop(args, check=True, data=None):
            if args[:2] == ['systemctl', 'stop'] and args[-1].startswith(security.UNIT + '-'):
                raise security.SecurityCommandError('Simulated timer-stop failure.')
            return self.fake_run(args, check, data)

        with patch.object(security, 'run', fail_timer_stop):
            with self.assertRaisesRegex(security.SecurityCommandError, 'timer-stop'):
                self.confirm(staged['token'])
        self.assertTrue((self.state / 'pending.json').exists())
        self.assertTrue(security.rollback(staged['token'])['rolled_back'])
        self.assertEqual(security.read_json(self.state / 'baseline.json')['expected'], before)
        self.assertTrue(security.reset_preview()['available'])

    def test_legacy_ssh_tracking_requires_verified_before_state_and_exact_app_transform(self):
        security.prepare_legacy_ssh()
        original = self.main.read_bytes()
        self.main.write_bytes(b'Include /etc/ssh/ashapp.conf\n' + original)
        security.LEGACY_SSH.write_bytes(b'PubkeyAuthentication yes\nPermitRootLogin no\n')
        security.record_legacy_ssh()
        self.assertTrue(security.reset_preview()['available'])
        tracked = security.read_json(self.state / 'baseline.json')['expected'].copy()
        self.main.write_text(self.main.read_text() + '# outside edit\n')
        with self.assertRaisesRegex(ValueError, 'outside Ashapp'):
            security.prepare_legacy_ssh()
        self.assertEqual(security.read_json(self.state / 'baseline.json')['expected'], tracked)

    def test_legacy_ssh_completion_does_not_adopt_external_edit_after_preparation(self):
        security.prepare_legacy_ssh()
        tracked = security.read_json(self.state / 'baseline.json')['expected'].copy()
        self.main.write_text('Include /etc/ssh/ashapp.conf\n' + self.main.read_text() + '# concurrent administrative edit\n')
        security.LEGACY_SSH.write_text('PubkeyAuthentication yes\n')
        with self.assertRaisesRegex(ValueError, 'Outside edits were not adopted'):
            security.record_legacy_ssh()
        self.assertEqual(security.read_json(self.state / 'baseline.json')['expected'], tracked)

    def exercise_legacy_candidate(self, previous_extra, resulting_extra):
        security.LEGACY_SSH.write_bytes(previous_extra)
        security.prepare_legacy_ssh()
        self.main.write_bytes(b'Include /etc/ssh/ashapp.conf\n' + self.main.read_bytes())
        security.LEGACY_SSH.write_bytes(resulting_extra)
        security.record_legacy_ssh()
        self.assertEqual(security.LEGACY_SSH.read_bytes(), resulting_extra)
        self.assertTrue(security.reset_preview()['available'])

    def test_legacy_keep_accepts_an_unterminated_root_policy_record(self):
        self.exercise_legacy_candidate(b'PubkeyAuthentication no\nPermitRootLogin no',
                                       b'PubkeyAuthentication yes\nPermitRootLogin no')

    def test_legacy_keep_preserves_crlf_on_the_selected_root_policy_record(self):
        self.exercise_legacy_candidate(b'# original\r\nPermitRootLogin no\r\n# ignored\r\n',
                                       b'PubkeyAuthentication yes\nPermitRootLogin no\r\n')

    def test_legacy_root_denial_accepts_printf_lf_after_unterminated_input(self):
        self.exercise_legacy_candidate(b'PermitRootLogin prohibit-password',
                                       b'PubkeyAuthentication yes\nPermitRootLogin no\n')

    def test_unconfirmed_reset_restores_enabled_boot_policy_for_all_managed_units(self):
        units = ('fail2ban.service', 'apt-daily.timer', 'apt-daily-upgrade.timer', 'netfilter-persistent.service')
        state = {unit: {'active': False, 'enabled': 'disabled'} for unit in units}

        def command(args, check=True, data=None):
            if args[0] == 'systemctl':
                targets = [unit for unit in args[2:] if unit in state]
                if args[1] == 'is-enabled' and targets:
                    value = state[targets[0]]['enabled']
                    return SimpleNamespace(returncode=0 if value == 'enabled' else 1, stdout=value + '\n', stderr='')
                for unit in targets:
                    if args[1] in ('enable', 'disable'):
                        state[unit]['enabled'] = 'enabled' if args[1] == 'enable' else 'disabled'
                        if '--now' in args: state[unit]['active'] = args[1] == 'enable'
                    elif args[1] in ('start', 'stop'):
                        state[unit]['active'] = args[1] == 'start'
            return self.fake_run(args, check, data)

        with patch.object(security, 'run', command), \
                patch.object(security, 'active', side_effect=lambda unit: state.get(unit if '.' in unit else unit + '.service', {}).get('active', False)):
            security.capture_baseline()
            for unit in units: state[unit] = {'active': True, 'enabled': 'enabled'}
            staged = self.stage({'firewall': True}); self.confirm(staged['token'])
            reset = security.reset_stage(security.reset_preview()['digest'])
            self.assertTrue(all(value == {'active': False, 'enabled': 'disabled'} for value in state.values()))
            self.assertTrue(security.rollback(reset['token'])['rolled_back'])
            self.assertTrue(all(value == {'active': True, 'enabled': 'enabled'} for value in state.values()))
            self.assertFalse((self.state / 'pending.json').exists())

    def test_failed_unconfirmed_reset_recovers_hardened_policy(self):
        staged = self.stage({'disable_root': True, 'firewall': True}); self.confirm(staged['token'])
        hardened = self.main.read_text()
        plan = security.reset_preview()
        staged_reset = security.reset_stage(plan['digest'])
        security.rollback(staged_reset['token'])
        self.assertEqual(self.main.read_text(), hardened)
        self.assertTrue(self.files['firewall'].exists())
        self.assertTrue(security.diagnostics()['firewall']['enabled'])

    def test_disabled_ssh_switch_restores_original_policy_instead_of_widening_it(self):
        staged = self.stage({'disable_root': True}); self.confirm(staged['token'])
        # The production Include is absolute; its parser is covered separately.
        with patch.object(security, 'ssh_policy'):
            staged = self.stage({'disable_root': False}); self.confirm(staged['token'])
        self.assertIn('PermitRootLogin prohibit-password', self.files['ssh'].read_text())

    def test_saved_stopped_vpn_listener_is_included_in_firewall_preview(self):
        directory = security.AWG_DIRECTORY; directory.mkdir()
        (directory / 'params').write_text('SERVER_AWG_NIC=awg0\n')
        (directory / 'awg0.conf').write_text('[Interface]\nListenPort = 586\n')
        plan = security.preview({'firewall': True})
        self.assertIn(586, plan['ports']['udp'])

    def test_safe_command_diagnostics_identify_logfile_failure_without_echoing_output(self):
        result = SimpleNamespace(returncode=255, stdout='password=never-print', stderr='Have not found any log file for sshd jail')
        message = security.command_failure(['fail2ban-client', '-t'], result)
        self.assertIn('log file', message)
        self.assertIn('exit 255', message)
        self.assertNotIn('never-print', message)

    def test_recovery_stops_new_fail2ban_before_restoring_invalid_unused_default(self):
        daemon = {'running': False}

        def command(args, check=True, data=None):
            if args[:2] == ['systemctl', 'enable'] and args[-1] == 'fail2ban':
                daemon['running'] = True
            if args[:2] == ['systemctl', 'stop'] and args[-1] in ('fail2ban', 'fail2ban.service'):
                daemon['running'] = False
            if args == ['fail2ban-client', '-t'] and not self.files['fail2ban'].exists():
                raise security.SecurityCommandError('The unused distro default expects absent file logs.')
            return self.fake_run(args, check, data)

        with patch.object(security, 'run', command), \
                patch.object(security, 'active', side_effect=lambda unit: daemon['running'] if unit.removesuffix('.service') == 'fail2ban' else False), \
                patch.object(security.shutil, 'which', return_value='/usr/bin/fail2ban-client'):
            staged = self.stage({'fail2ban': True})
            self.assertTrue(daemon['running'])
            self.assertTrue(security.rollback(staged['token'])['rolled_back'])
            self.assertFalse(daemon['running'])
            self.assertFalse((self.state / 'pending.json').exists())

    def test_failed_component_diagnostics_do_not_hide_other_security_results(self):
        self.files['firewall'].write_text('{malformed')
        result = security.diagnostics()
        self.assertIn('error', result['firewall'])
        self.assertIsNotNone(result['ssh'])
        self.assertIsNotNone(result['listeners'])

    def test_foreign_early_drop_does_not_pass_firewall_rule_membership_check(self):
        staged = self.stage({'firewall': True}); self.confirm(staged['token'])
        config = security.read_json(self.files['firewall'])
        rules = self.chains['iptables', 'ASHAPP-IN']
        rules.insert(0, rules.pop())
        self.assertFalse(security.firewall_status(config, [])['enabled'])

    @unittest.skipIf(os.name == 'nt', 'POSIX descriptor modes')
    def test_recovery_restores_modes_under_production_umask(self):
        self.main.chmod(0o640)
        previous = os.umask(0o077)
        try:
            staged = self.stage({'disable_passwords': True})
            security.rollback(staged['token'])
            self.assertEqual(self.main.stat().st_mode & 0o777, 0o640)
            self.assertEqual(security.RECOVERY.stat().st_mode & 0o777, 0o644)
            self.assertEqual(security.HELPER.stat().st_mode & 0o777, 0o700)
        finally:
            os.umask(previous)

    @unittest.skipIf(os.name == 'nt', 'POSIX owner/directory permissions')
    def test_writable_security_parent_is_refused_before_any_changes(self):
        self.root.chmod(0o777)
        try:
            with self.assertRaisesRegex(ValueError, 'no group/other write'):
                security.preview({'firewall': True})
            self.assertEqual(list(self.state.iterdir()), [])
        finally:
            self.root.chmod(0o700)

    @unittest.skipIf(os.name == 'nt', 'POSIX directory traversal')
    def test_new_shared_firewall_parent_does_not_block_later_unprivileged_vless(self):
        self.files['firewall'] = self.root / 'shared-config' / 'firewall.json'
        previous = os.umask(0o077)
        try:
            staged = self.stage({'firewall': True}); self.confirm(staged['token'])
            self.assertEqual(self.files['firewall'].parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(self.files['firewall'].stat().st_mode & 0o777, 0o600)
            self.files['firewall'].parent.chmod(0o700)
            staged = self.stage({'firewall': True}); self.confirm(staged['token'])
            self.assertEqual(self.files['firewall'].parent.stat().st_mode & 0o777, 0o700)
        finally:
            os.umask(previous)

    @unittest.skipIf(os.name == 'nt', 'POSIX advisory file locks')
    def test_recovery_waits_for_a_contended_lock_instead_of_skipping_its_only_attempt(self):
        import fcntl
        import select
        import subprocess
        code = '''import importlib.util,sys
spec=importlib.util.spec_from_file_location('security',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with open(sys.argv[2], 'a') as lock:
 print('waiting',flush=True)
 module.acquire_lock(lock,sys.argv[3])
 print('acquired',flush=True)
'''
        path = self.root / 'recovery.lock'
        for action in ('rollback', 'recover', 'firewall-restore'):
            with self.subTest(action=action), path.open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                child = subprocess.Popen([sys.executable, '-c', code, str(ROOT / 'server/security_manager.py'), str(path), action],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    self.assertEqual(child.stdout.readline().strip(), 'waiting')
                    ready, _, _ = select.select([child.stdout], [], [], 0.2)
                    self.assertEqual(ready, [], 'Recovery exited or bypassed the held lock.')
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    output, error = child.communicate(timeout=5)
                    self.assertEqual(child.returncode, 0, error)
                    self.assertEqual(output.strip(), 'acquired')
                finally:
                    child.kill() if child.poll() is None else None
                    child.communicate()


if __name__ == '__main__': unittest.main()

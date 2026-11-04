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
                                if args[1] == 'enable': state.update(active=True, enabled='enabled')
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
        self.assertFalse(security.firewall_status(config, ports + [{'protocol': 'tcp', 'port': 1081}])['enabled'])
        staged = self.stage({'firewall': False}); self.confirm(staged['token'])
        self.assertFalse(security.DOCKER_DROPIN.exists())

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

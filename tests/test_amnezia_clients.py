"""Exercise client management and the actual transaction Bash with synthetic files/tools."""
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('amnezia_test', Path(__file__).resolve().parents[1] / 'server/amnezia_clients.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def key(n):
    return base64.b64encode(bytes([n]) * 32).decode()


def fields(text):
    return dict(line.split('=', 1)[0].strip() and (line.split('=', 1)[0].strip(), line.split('=', 1)[1].strip())
                for line in text.splitlines() if '=' in line and not line.lstrip().startswith('#'))


def peers(text):
    return [fields(s) for s in text.split('[Peer]')[1:]]


class ManagementTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        self.config = ('[Interface]\nAddress = 10.8.0.1/29\nListenPort = 51820\nPrivateKey = ' + key(1) +
                       '\nJc = 4\nS4 = 11\nContentPaddingAddition = 3\n\n[Peer]\nPublicKey = ' + key(2) +
                       '\nPresharedKey = ' + key(3) + '\nAllowedIPs = 10.8.0.2/32\n')
        self.table = json.dumps([{'clientId': key(2), 'userData': {'clientName': 'Existing', 'extra': 7}}])
        self.runtime = self.config + '\n[Peer]\nPublicKey = ' + key(9) + '\nAllowedIPs = 10.8.0.3/32\n'
        self.transactions = []
        self.calls = []
        self.published_port = 585
        self.interface_running = True
        self.failure = None
        self.manager = module.ContainerClients('amnezia-awg2', self.run_command, self.write, fields, peers, self.directory)

    def write(self, path, content, mode=0o600):
        path.write_bytes(content.encode('utf-8'))
        path.chmod(mode)

    def run_command(self, args, data=None, check=True):
        self.calls.append(args)
        result = ''
        if 'bash' in args:
            self.transactions.append((args, data))
            if self.failure:
                return subprocess.CompletedProcess(args, 1, self.failure, '')
            lines = data.splitlines()
            self.assertEqual(lines[0], hashlib.sha256(self.config.encode()).hexdigest())
            self.config, self.table = [base64.b64decode(s).decode() for s in lines[3:5]]
            result = 'ASHAPP_TX_OK\n'
        elif args[1] == 'port':
            result = f'0.0.0.0:{self.published_port}\n[::]:{self.published_port}\n'
        elif args[4] == 'base64':
            value = self.table if args[-1].endswith('clientsTable') else self.config
            result = base64.b64encode(value.encode('utf-8')).decode()
        elif args[5] == 'showconf':
            if not self.interface_running:
                raise RuntimeError('Synthetic stopped interface')
            result = self.runtime
        elif args[5] == 'genkey':
            result = key(4)
        elif args[5] == 'genpsk':
            result = key(5)
        elif args[5] == 'pubkey':
            result = {key(4): key(6), key(10): key(2)}.get(data.strip(), key(7))
        return subprocess.CompletedProcess(args, 0, result, '')

    def test_create_reserves_runtime_only_addresses_and_exports_correct_port_extensions(self):
        result = self.manager.add('New phone', '203.0.113.10', '9.9.9.9')
        self.assertEqual(result['public_key'], key(6))
        text = self.manager.export(key(6))['config']
        self.assertIn('Address = 10.8.0.4/32', text)
        self.assertIn('Endpoint = 203.0.113.10:585', text)
        self.assertIn('ContentPaddingAddition = 3', text)
        self.assertIn('S4 = 11', text)
        self.assertIn(key(2), self.config)
        self.assertEqual(json.loads(self.table)[0]['userData']['extra'], 7)
        args, payload = self.transactions[0]
        self.assertNotIn(key(4), ' '.join(args))
        self.assertNotIn('New phone', ' '.join(args))
        self.assertTrue(payload)

    def test_rename_preserves_keys_and_unknown_metadata_in_both_schemas(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                self.table = json.dumps({key(2): {'clientName': 'Existing', 'extra': 7}} if legacy else
                                        [{'clientId': key(2), 'userData': {'clientName': 'Existing', 'extra': 7}}])
                before = self.config
                self.manager.rename(key(2), 'Новый телефон')
                self.assertEqual(self.config, before)
                obj = json.loads(self.table)
                data = obj[key(2)] if legacy else obj[0]['userData']
                self.assertEqual(data, {'clientName': 'Новый телефон', 'extra': 7})
                self.assertEqual(self.transactions[-1][0][-1], 'rename')

    def test_revoke_uses_key_and_keeps_unrelated_peer(self):
        self.config += '\n[Peer]\nPublicKey = ' + key(8) + '\nAllowedIPs = 10.8.0.5/32\n'
        self.manager.revoke(key(2))
        self.assertNotIn(key(2), self.config)
        self.assertIn(key(8), self.config)
        self.assertEqual(json.loads(self.table), [])
        payload = self.transactions[0][1].splitlines()
        self.assertIn(key(3), base64.b64decode(payload[6]).decode())

    def test_missing_private_key_is_not_regenerated_or_exported(self):
        with self.assertRaisesRegex(RuntimeError, 'cannot be recovered'):
            self.manager.export(key(2))
        self.assertFalse(self.transactions)

    def test_legacy_container_uses_wg_and_preserves_legacy_table(self):
        self.manager = module.ContainerClients('amnezia-awg', self.run_command, self.write, fields, peers, self.directory)
        self.table = json.dumps({key(2): {'clientName': 'Existing', 'extra': 7}})
        self.manager.add('Phone', '203.0.113.10', '1.1.1.1')
        self.assertEqual(self.transactions[-1][0][-2], 'wg')
        self.assertIsInstance(json.loads(self.table), dict)

    def test_broad_routes_are_reserved_and_names_never_become_shell_program_text(self):
        before = self.config
        self.runtime += '\n[Peer]\nPublicKey = ' + key(8) + '\nAllowedIPs = 10.8.0.0/29\n'
        with self.assertRaisesRegex(RuntimeError, 'No addresses'):
            self.manager.add('Phone', '203.0.113.10', '1.1.1.1')
        self.assertEqual(self.config, before)
        self.runtime = before
        self.manager.rename(key(2), '$(touch should-not-run)')
        self.assertNotIn('should-not-run', ' '.join(self.transactions[-1][0]))

    def test_export_rejects_stale_server_or_client_keys(self):
        self.manager.add('New phone', '203.0.113.10', '1.1.1.1')
        path = self.manager.export_path(key(6))
        path.write_text(path.read_text().replace(key(7), key(8)))
        with self.assertRaisesRegex(RuntimeError, 'no longer matches'):
            self.manager.export(key(6))

    def test_duplicate_names_malformed_tables_and_invalid_sources_do_not_mutate(self):
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.manager.add('Existing', '203.0.113.10', '1.1.1.1')
        self.table = '{'
        with self.assertRaisesRegex(RuntimeError, 'malformed'):
            self.manager.rename(key(2), 'Name')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported VPN source'):
            module.ContainerClients('amnezia-awg; touch bad', self.run_command, self.write, fields, peers, self.directory)
        self.assertFalse(self.transactions)

    def test_confirmed_rollback_removes_new_export_but_unknown_outcome_retains_recovery_key(self):
        self.failure = 'ASHAPP_TX_ROLLED_BACK\n'
        with self.assertRaises(RuntimeError):
            self.manager.add('Phone', '203.0.113.10', '1.1.1.1')
        self.assertFalse(self.manager.export_path(key(6)).exists())
        self.failure = 'ASHAPP_TX_RECOVERY_REQUIRED\n'
        with self.assertRaisesRegex(RuntimeError, 'needs recovery'):
            self.manager.add('Phone', '203.0.113.10', '1.1.1.1')
        self.assertTrue(self.manager.export_path(key(6)).exists())

    def original_configuration(self):
        return ('[Interface]\nPrivateKey = ' + key(10) + '\nAddress = 10.8.0.2/32\nS4 = 11\n'
                '[Peer]\nPublicKey = ' + key(7) + '\nPresharedKey = ' + key(3) +
                '\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:585\n')

    def test_reopening_existing_config_reuses_bytes_without_generating_keys(self):
        content = self.original_configuration().replace('\n', '\r\n')
        self.manager.import_configuration(key(2), content)
        self.calls.clear()
        self.assertEqual(self.manager.export(key(2))['config'], content)
        self.assertEqual(self.manager.export(key(2))['config'], content)
        self.assertFalse(any('genkey' in args or 'genpsk' in args or 'bash' in args for args in self.calls))

    def test_export_does_not_depend_on_names_table_or_running_interface(self):
        self.manager.import_configuration(key(2), self.original_configuration())
        self.table = 'invalid json'
        self.interface_running = False
        self.assertEqual(self.manager.export(key(2))['config'], self.original_configuration())

    def test_import_checks_identity_hooks_and_explicit_replacement_without_changing_access(self):
        content = self.original_configuration()
        before = self.config
        with self.assertRaisesRegex(RuntimeError, 'no longer matches'):
            self.manager.import_configuration(key(2), content.replace(key(10), key(4)))
        with self.assertRaisesRegex(RuntimeError, 'unsupported'):
            self.manager.import_configuration(key(2), content.replace('Address =', 'PostUp = echo bad\nAddress ='))
        self.manager.import_configuration(key(2), content)
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.manager.import_configuration(key(2), content)
        self.manager.import_configuration(key(2), content, replace=True)
        self.assertEqual(self.config, before)
        self.assertFalse(self.transactions)

    def test_export_rejects_stale_addresses_obfuscation_and_public_port(self):
        self.manager.import_configuration(key(2), self.original_configuration())
        original = self.config
        for changed in (original.replace('10.8.0.2/32', '10.8.0.5/32'), original.replace('S4 = 11', 'S4 = 33')):
            with self.subTest(changed=changed):
                self.config = changed
                with self.assertRaisesRegex(RuntimeError, 'no longer match'):
                    self.manager.export(key(2))
        self.config = original
        self.published_port = 9999
        with self.assertRaisesRegex(RuntimeError, 'no longer match'):
            self.manager.export(key(2))

    def test_crlf_snapshots_keep_original_hash_bytes(self):
        self.config = self.config.replace('\n', '\r\n')
        self.manager.rename(key(2), 'Renamed')
        self.assertIn('\r\n', self.config)

    def test_revoke_reports_cleanup_warning_without_claiming_access_is_still_active(self):
        from unittest.mock import patch
        with patch.object(Path, 'unlink', side_effect=PermissionError('synthetic export cleanup failure')):
            result = self.manager.revoke(key(2))
        self.assertTrue(result['revoked'])
        self.assertIn('could not be erased', result['warning'])
        self.assertNotIn(key(2), self.config)


class TransactionTests(unittest.TestCase):
    def run_transaction(self, operation='add', fail='', conflict=False):
        bash = Path('C:/Program Files/Git/bin/bash.exe')
        if not bash.exists():
            import shutil
            command = shutil.which('bash')
            if not command:
                self.skipTest('Bash unavailable')
            bash = Path(command)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old = '[Interface]\n# original\n'
            new = '[Interface]\n# changed\n'
            (root / 'awg0.conf').write_bytes(old.encode())
            (root / 'clientsTable').write_bytes(b'[]\n')
            (root / 'runtime').write_bytes(('other\n' + ('target\n' if operation == 'revoke' else '')).encode())
            prefix = r'''
awg() {
  if [[ "$1" == addconf ]]; then
    if [[ "$FAIL" == apply ]]; then return 1; fi
    printf 'target\n' >> "$TEST_ROOT/runtime"
  elif [[ "$1" == set ]]; then
    grep -v '^target$' "$TEST_ROOT/runtime" > "$TEST_ROOT/runtime.new" || true
    mv "$TEST_ROOT/runtime.new" "$TEST_ROOT/runtime"
  elif [[ "$1" == show ]]; then
    if [[ "$FAIL" == verify ]]; then return 1; fi
    cat "$TEST_ROOT/runtime"
  fi
}
mv() {
  if [[ "$FAIL" == table && "$2" == clientsTable ]]; then return 1; fi
  command mv "$@"
}
'''
            program = prefix + module.TRANSACTION.replace('cd /opt/amnezia/awg', 'cd "$TEST_ROOT"')
            lines = [('bad' if conflict else hashlib.sha256(old.encode()).hexdigest()),
                     hashlib.sha256(b'[]\n').hexdigest(), 'target']
            lines += [base64.b64encode(v.encode()).decode() for v in (new, '[{}]\n', '[Peer]\n', '[Peer]\n')]
            env = dict(os.environ, TEST_ROOT=root.as_posix(), FAIL=fail)
            result = subprocess.run([str(bash), '-c', program, '--', 'awg0', 'awg', operation],
                                    input=('\n'.join(lines) + '\n').encode(), capture_output=True, env=env)
            result = subprocess.CompletedProcess(result.args, result.returncode, result.stdout.decode(), result.stderr.decode())
            return result, (root / 'awg0.conf').read_text(), (root / 'clientsTable').read_text(), \
                (root / 'runtime').read_text(), (root / '.ashapp-client-lock').exists()

    def test_actual_bash_applies_only_target_and_removes_private_staging(self):
        result, config, table, runtime, locked = self.run_transaction()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ASHAPP_TX_OK', result.stdout)
        self.assertIn('changed', config)
        self.assertIn('other', runtime)
        self.assertIn('target', runtime)
        self.assertFalse(locked)

    def test_actual_bash_rolls_back_when_live_apply_or_table_write_fails(self):
        for failure in ('apply', 'table'):
            with self.subTest(failure=failure):
                result, config, table, runtime, locked = self.run_transaction(fail=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ASHAPP_TX_ROLLED_BACK', result.stdout)
                self.assertIn('original', config)
                self.assertEqual(table, '[]\n')
                self.assertEqual(runtime, 'other\n')
                self.assertFalse(locked)

    def test_actual_bash_rejects_stale_snapshot_before_changes(self):
        result, config, table, runtime, locked = self.run_transaction(conflict=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('original', config)
        self.assertEqual(runtime, 'other\n')
        self.assertFalse(locked)

    def test_actual_bash_revokes_only_target(self):
        result, config, table, runtime, locked = self.run_transaction(operation='revoke')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(runtime, 'other\n')
        self.assertFalse(locked)

    def test_failed_rollback_verification_retains_private_lock_and_recovery_state(self):
        result, config, table, runtime, locked = self.run_transaction(fail='verify')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ASHAPP_TX_RECOVERY_REQUIRED', result.stdout)
        self.assertTrue(locked)


if __name__ == '__main__':
    unittest.main()

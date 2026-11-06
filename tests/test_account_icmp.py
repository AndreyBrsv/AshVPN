"""Exercise account and ICMP failure boundaries with fake shell commands."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')
BASH = 'C:/Program Files/Git/bin/bash.exe' if Path('C:/Program Files/Git/bin/bash.exe').exists() else shutil.which('bash')


@unittest.skipUnless(BASH, 'Bash is required')
class AccountIcmpTests(unittest.TestCase):
    def test_password_commit_markers_surround_only_the_successful_write(self):
        for action, start, end, payload, identity in (
                ('create_user', 'create_user() {', '\nssh_config() {', 'testadmin\0placeholder_password\0', 'administrator'),
                ('root_password', 'root_password() {', '\ncreate_user() {', 'placeholder_password\0', 'root-password')):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                body = SOURCE[SOURCE.index(start):SOURCE.index(end)]
                script = '''set -e
BASE_DIR=/unused-test-helpers
header() { :; }
field() { IFS= read -r -d '' "$1"; }
username_ok() { return 0; }
id() { printf '1001\\n'; }
fatal() { exit 99; }
ok() { :; }
usermod() { :; }
visudo() { :; }
install() { :; }
python3() { printf 'MARKER:%s:%s\\n' "$3" "$4"; }
chpasswd() { cat >/dev/null; printf 'PASSWORD_COMMITTED\\n'; }
''' + body.replace('/etc/sudoers.d', Path(folder).as_posix()) + '\n' + action + '\n'
                result = subprocess.run([BASH, '-c', script], input=payload, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [f'MARKER:{identity}:started', 'PASSWORD_COMMITTED', f'MARKER:{identity}:committed'])
                self.assertNotIn('placeholder_password', result.stdout + result.stderr)

    def test_account_preparation_failures_do_not_commit_new_password(self):
        body = SOURCE[SOURCE.index('create_user() {'):SOURCE.index('\nssh_config() {')]
        for failing in ('usermod', 'visudo'):
            with tempfile.TemporaryDirectory() as folder:
                folder = Path(folder).as_posix()
                script = '''set -e
header() { :; }
field() { IFS= read -r -d '' "$1"; }
username_ok() { return 0; }
id() { printf '1001\\n'; }
fatal() { exit 99; }
ok() { :; }
chpasswd() { printf 'PASSWORD_COMMITTED\\n'; }
usermod() { :; }
visudo() { :; }
install() { :; }
''' + f'{failing}() {{ return 23; }}\n' + body.replace('/etc/sudoers.d', folder) + '\ncreate_user\n'
                result = subprocess.run([BASH, '-c', script], input='testadmin\0placeholder_password\0', text=True, capture_output=True)
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertNotIn('PASSWORD_COMMITTED', result.stdout)

    def test_unblock_does_not_delete_unowned_rules_or_execute_legacy_plugin(self):
        body = SOURCE[SOURCE.index('    icmp-unblock)'):SOURCE.index('    reboot)')]
        for existing in (False, True):
            with tempfile.TemporaryDirectory() as folder:
                plugin = Path(folder) / 'plugin'
                if existing:
                    plugin.write_text('#!/bin/sh\necho LEGACY_PLUGIN_EXECUTED\n')
                    plugin.chmod(0o755)
                body_fixture = body.replace('/usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp', plugin.as_posix())
                script = '''set -e
fatal() { exit 77; }
ok() { :; }
iptables() { printf 'FOREIGN_RULE_TOUCHED\\n'; return 1; }
case icmp-unblock in
''' + body_fixture + '\nesac\n'
                result = subprocess.run([BASH, '-c', script], text=True, capture_output=True)
                self.assertNotIn('FOREIGN_RULE_TOUCHED', result.stdout)
                self.assertNotIn('LEGACY_PLUGIN_EXECUTED', result.stdout)
                self.assertEqual(plugin.exists(), existing)


if __name__ == '__main__':
    unittest.main()

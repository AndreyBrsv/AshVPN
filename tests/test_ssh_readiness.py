"""Model socket-activated OpenSSH upgrade without touching a real service."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = 'C:/Program Files/Git/bin/bash.exe' if Path('C:/Program Files/Git/bin/bash.exe').exists() else shutil.which('bash')
SOURCE = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')


@unittest.skipUnless(BASH, 'Bash is required')
class SshReadinessTests(unittest.TestCase):
    def test_package_actions_restore_runtime_before_testing_ssh_policy(self):
        helpers = SOURCE[SOURCE.index('ensure_ssh_ready() {'):SOURCE.index('\nroot_password() {')]
        for action in ('dependencies', 'upgrade'):
            with self.subTest(action=action):
                script = '''set -e
SSH_RUNTIME=0
header() { :; }
ok() { :; }
warn() { :; }
debconf-set-selections() { cat >/dev/null; }
apt-get() { SSH_RUNTIME=0; printf 'PACKAGE_ACTION\\n'; }
systemctl() {
    [[ "$1 $2" == 'start ssh' ]] || exit 81
    SSH_RUNTIME=1
    printf 'SSH_STARTED\\n'
}
sshd_fixture() { (( SSH_RUNTIME == 1 )) || exit 82; printf 'POLICY_VERIFIED\\n'; }
''' + helpers.replace('/usr/sbin/sshd', 'sshd_fixture') + f'\n{action}\nsshd_fixture -T\n'
                result = subprocess.run([BASH, '-c', script], text=True, encoding='utf-8', capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertLess(result.stdout.rindex('PACKAGE_ACTION'), result.stdout.index('SSH_STARTED'))
                self.assertLess(result.stdout.index('SSH_STARTED'), result.stdout.index('POLICY_VERIFIED'))

    def test_service_name_fallback_and_failed_start_stop_validation(self):
        helper = SOURCE[SOURCE.index('ensure_ssh_ready() {'):SOURCE.index('\ndependencies() {')]
        for fallback_succeeds in (False, True):
            with self.subTest(fallback_succeeds=fallback_succeeds):
                script = '''set -e
ok() { :; }
systemctl() {
    printf 'START %s\\n' "$2"
    if [[ "$2" == ssh ]]; then return 1; fi
''' + ('return 0' if fallback_succeeds else 'return 23') + '''
}
sshd_fixture() { printf 'VALIDATED\\n'; }
''' + helper.replace('/usr/sbin/sshd', 'sshd_fixture') + '\nensure_ssh_ready\n'
                result = subprocess.run([BASH, '-c', script], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0 if fallback_succeeds else 23, result.stderr)
                self.assertIn('START ssh\nSTART sshd', result.stdout)
                self.assertEqual('VALIDATED' in result.stdout, fallback_succeeds)

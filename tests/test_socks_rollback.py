"""Exercise rollback with a fake Docker function; never contact a daemon."""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = 'C:/Program Files/Git/bin/bash.exe' if Path('C:/Program Files/Git/bin/bash.exe').exists() else shutil.which('bash')


class SocksRollbackTests(unittest.TestCase):
    def test_private_engine_preflight_precedes_build_or_container_mutation_and_public_is_unchanged(self):
        source = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')
        ready = source[source.index('docker_ready() {'):source.index('\nsocks_install() {')]
        install = source[source.index('socks_install() {'):source.index('\ncase "$ACTION" in')]
        for mode in ('private', 'public'):
            script = '''set -e
BASE_DIR=/fake-ashapp
header() { :; }
field() { IFS= read -r -d '' "$1"; }
port_ok() { return 0; }
fatal() { exit 99; }
python3() { printf 'PREFLIGHT %s\\n' "$*" >&2; return 86; }
systemctl() { printf 'DAEMON_ACTIVATED\\n' >&2; }
docker() { [[ "$1" == info ]]; }
install() { printf 'MUTATION\\n' >&2; return 23; }
''' + ready + install + '\nsocks_install\n'
            result = subprocess.run([BASH, '-c', script], input='1080\0test\0test_placeholder\0yes\0' + mode + '\0',
                                    capture_output=True, text=True)
            if mode == 'private':
                self.assertEqual(result.returncode, 86)
                self.assertIn('clients.py socks-private-ready', result.stderr)
                self.assertNotIn('MUTATION', result.stderr)
                self.assertNotIn('DAEMON_ACTIVATED', result.stderr)
            else:
                self.assertEqual(result.returncode, 23)
                self.assertNotIn('PREFLIGHT', result.stderr)
                self.assertIn('DAEMON_ACTIVATED', result.stderr)

    def test_rollback_preserves_previous_running_or_stopped_state(self):
        source = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')
        handler = source[source.index('on_error() {'):source.index('\nif [[ "$ACTION" == --help')]
        for running in ('true', 'false'):
            with self.subTest(running=running):
                script = '''set +e
exec 3>&1
docker() { printf 'DOCKER %s\\n' "$*" >&3; }
restore_ssh() { :; }
cleanup() { :; }
err() { :; }
ACTION=test
SOCKS_NEW=1
SOCKS_BACKUP=old-container
''' + f'SOCKS_WAS_RUNNING={running}\n' + handler + '\nfalse\non_error 1 test\n'
                result = subprocess.run([BASH, '-c', script], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn('DOCKER rm -f amnezia-socks5proxy', result.stdout)
                self.assertIn('DOCKER rename old-container amnezia-socks5proxy', result.stdout)
                self.assertEqual('DOCKER start amnezia-socks5proxy' in result.stdout, running == 'true')

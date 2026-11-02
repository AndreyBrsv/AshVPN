"""Exercise rollback with a fake Docker function; never contact a daemon."""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = 'C:/Program Files/Git/bin/bash.exe' if Path('C:/Program Files/Git/bin/bash.exe').exists() else shutil.which('bash')


class SocksRollbackTests(unittest.TestCase):
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

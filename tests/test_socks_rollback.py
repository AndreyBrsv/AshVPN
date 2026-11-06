"""Exercise rollback with a fake Docker function; never contact a daemon."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = 'C:/Program Files/Git/bin/bash.exe' if Path('C:/Program Files/Git/bin/bash.exe').exists() else shutil.which('bash')


class SocksRollbackTests(unittest.TestCase):
    def test_same_named_image_is_not_treated_as_an_existing_socks_container(self):
        source = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')
        body = source[source.index('socks_install() {'):source.index('\ncase "$ACTION" in')]
        for image_present in (0, 1):
            with tempfile.TemporaryDirectory() as folder, self.subTest(image_present=image_present):
                body_fixture = body.replace('directory=/opt/ashapp/socks5', 'directory=' + folder.replace('\\', '/'))
                script = '''set -e
BASE_DIR=/fake-ashapp
header() { :; }
field() { IFS= read -r -d '' "$1"; }
port_ok() { return 0; }
fatal() { exit 99; }
python3() { :; }
docker_ready() { :; }
install() { :; }
docker() {
    case "$1" in
        build) IMAGE_PRESENT=1 ;;
        inspect)
            if [[ "$2 $3" == '--type container' ]]; then return 1; fi
            if (( IMAGE_PRESENT == 0 )); then return 1; fi
            if [[ "$2" == -f ]]; then return 66; fi
            printf 'IMAGE_NOT_CONTAINER\\n'
            ;;
        run) printf 'CREATING_NEW_CONTAINER\\n' >&2; return 42 ;;
        stop|rename) printf 'WRONG_CONTAINER_REPLACEMENT\\n' >&2; return 67 ;;
    esac
}
''' + f'IMAGE_PRESENT={image_present}\n' + body_fixture + '\nsocks_install\n'
                result = subprocess.run([BASH, '-c', script],
                                        input='1080\0test\0test_placeholder\0no\0private\0',
                                        capture_output=True, text=True, encoding='utf-8')
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertIn('CREATING_NEW_CONTAINER', result.stderr)
                self.assertNotIn('WRONG_CONTAINER_REPLACEMENT', result.stderr)

    def test_fresh_private_setup_installs_docker_before_engine_check_and_no_publication_precedes_it(self):
        source = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')
        body = source[source.index('docker_ready() {'):source.index('\ncase "$ACTION" in')]
        for check_result in (0, 86):
            with self.subTest(check_result=check_result):
                script = '''set -e
BASE_DIR=/fake-ashapp
DOCKER_PRESENT=0
header() { :; }
field() { IFS= read -r -d '' "$1"; }
port_ok() { return 0; }
fatal() { exit 99; }
command() {
    if [[ "$*" == '-v docker' ]]; then (( DOCKER_PRESENT == 1 ));
    else builtin command "$@"; fi
}
apt-get() { DOCKER_PRESENT=1; printf 'INSTALL_DOCKER\\n' >&2; }
systemctl() { printf 'DAEMON_ACTIVATED\\n' >&2; }
docker() { [[ "$1" == info ]]; }
install() { printf 'CONTAINER_PREPARATION\\n' >&2; return 23; }
''' + f'''python3() {{
    if [[ "$1" == */docker_setup.py ]]; then
        DOCKER_PRESENT=1; printf 'INSTALL_DOCKER\\nDAEMON_ACTIVATED\\n' >&2;
    else printf 'ENGINE_CHECK\\n' >&2; return {check_result}; fi
}}
''' + body + '\nsocks_install\n'
                result = subprocess.run([BASH, '-c', script],
                                        input='1080\0test\0test_placeholder\0no\0private\0',
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, check_result or 23, result.stderr)
                self.assertLess(result.stderr.index('INSTALL_DOCKER'), result.stderr.index('ENGINE_CHECK'))
                self.assertEqual('CONTAINER_PREPARATION' in result.stderr, check_result == 0)

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
python3() {
    if [[ "$1" == */docker_setup.py ]]; then printf 'DAEMON_INSPECTED\\n' >&2;
    else printf 'PREFLIGHT %s\\n' "$*" >&2; return 86; fi
}
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
                self.assertIn('DAEMON_INSPECTED', result.stderr)

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

import base64
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('amnezia_setup_tested', ROOT / 'server/amnezia_setup.py')
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)
AWG_SPEC = importlib.util.spec_from_file_location('awg_setup_reused', ROOT / 'server/awg_setup.py')
awg = importlib.util.module_from_spec(AWG_SPEC)
AWG_SPEC.loader.exec_module(awg)


def key(value):
    return base64.b64encode(bytes([value]) * 32).decode()


def result(text='', code=0):
    return SimpleNamespace(stdout=text, returncode=code, stderr='')


class DockerFixture:
    """Isolated command fixture; no Docker, network, kernel or system mutation."""
    def __init__(self, temporary):
        self.root = Path(temporary)
        self.AWG_DIR = self.root / 'host'
        self.AWG_DIR.mkdir()
        self.calls = []
        self.container = self.image = None
        self.extra_diff = ''
        self.kind = 'amneziawg'
        self.go = False
        self.fail_start = False
        self.fail_top = False
        self.fail_fallback_check = False
        self.process_go = False
        self.fields = ['203.0.113.10', '585', '1.1.1.1']
        self.arch = 'x86_64'
        self.networks = [
            {'Name': 'bridge', 'IPAM': {'Config': [{'Subnet': '172.17.0.0/16'}]}},
            {'Name': 'host', 'IPAM': {'Config': None}},
            {'Name': 'none', 'IPAM': {'Config': None}},
        ]
        self.chains = {
            'FORWARD': '-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n',
            'DOCKER-USER': '-N DOCKER-USER\n',
            'DOCKER-FORWARD': '-N DOCKER-FORWARD\n-A DOCKER-FORWARD -j DOCKER-CT\n-A DOCKER-FORWARD -j DOCKER-INTERNAL\n-A DOCKER-FORWARD -j DOCKER-BRIDGE\n-A DOCKER-FORWARD -i docker0 -j ACCEPT\n',
            'DOCKER-CT': '-N DOCKER-CT\n-A DOCKER-CT -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n',
            'DOCKER-BRIDGE': '-N DOCKER-BRIDGE\n-A DOCKER-BRIDGE -o docker0 -j DOCKER\n',
            'DOCKER-INTERNAL': '-N DOCKER-INTERNAL\n',
            'DOCKER': '-N DOCKER\n-A DOCKER ! -i docker0 -o docker0 -j DROP\n',
        }

    def read_fields(self):
        return self.fields

    def amnezia_containers(self):
        return [] if self.container is None else [{'source': shared.SOURCE}]

    def atomic_write(self, path, text, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8', newline='\n')
        path.chmod(mode)

    def run(self, args, data=None, check=True):
        self.calls.append((list(args), data))
        if args == ['uname', '-m']:
            return result(self.arch + '\n')
        if args[:3] == ['iptables', '-S', args[-1]]:
            return result(self.chains.get(args[-1], ''), 0 if args[-1] in self.chains else 1)
        if args[:3] == ['ip', '-j', '-4']:
            return result('[]')
        if args == ['pgrep', '-x', 'amneziawg-go']:
            return result(code=1)
        if args == ['docker', 'network', 'ls', '--quiet']:
            return result('bridge\nhost\nnone\n')
        if args[:3] == ['docker', 'network', 'inspect']:
            return result(json.dumps(self.networks))
        if args[:3] == ['docker', 'image', 'inspect']:
            return result(json.dumps([self.image]) if self.image else '', 0 if self.image else 1)
        if args[:4] == ['docker', 'inspect', '--type', 'container']:
            return result(json.dumps([self.container]) if self.container else '', 0 if self.container else 1)
        if args[:2] == ['docker', 'build']:
            self.image = {'Id': 'sha256:' + '2' * 64, 'Config': {'Labels': {
                'io.ashapp.managed': shared.OWNER,
                'io.ashapp.setup-id': args[args.index('--label') + 1].split('=', 1)[1]}}}
            return result()
        if args[:2] == ['docker', 'create']:
            labels = {args[i + 1].split('=', 1)[0]: args[i + 1].split('=', 1)[1] for i, a in enumerate(args) if a == '--label'}
            self.container = {'Id': '1' * 64, 'Image': self.image['Id'], 'Config': {'Labels': labels},
                              'State': {'Running': False},
                              'Mounts': [{'Type': 'bind', 'Source': str(shared.DIRECTORY / 'data'),
                                          'Destination': shared.CONTAINER_DATA, 'RW': True}],
                              'HostConfig': {'PortBindings': {'585/udp': [{'HostIp': '0.0.0.0', 'HostPort': '585'}]}}}
            return result(self.container['Id'] + '\n')
        if args[:2] in (['docker', 'start'], ['docker', 'restart']):
            if self.fail_start:
                raise RuntimeError('Synthetic activation failure.')
            self.container['State']['Running'] = True
            return result()
        if args[:2] == ['docker', 'stop']:
            self.container['State']['Running'] = False
            return result()
        if args[:3] == ['docker', 'rm', '-f']:
            self.container = None
            return result()
        if args[:3] == ['docker', 'image', 'rm']:
            self.image = None
            return result()
        if args[:2] == ['docker', 'diff']:
            return result('A /run/ashapp-kernel-ready\n' + self.extra_diff)
        if args[:3] == ['docker', 'exec', shared.SOURCE]:
            command = args[3:]
            if command == ['sha256sum', '/opt/amnezia/start.sh']:
                return result(shared.digest(shared.STARTUP) + '  /opt/amnezia/start.sh\n')
            if command == ['sh', '-c', '! command -v amneziawg-go >/dev/null 2>&1']:
                return result(code=125 if self.fail_fallback_check else (1 if self.go else 0))
            if command == ['ip', '-d', '-j', 'link', 'show', 'dev', 'awg0']:
                return result(json.dumps([{'flags': ['UP'], 'linkinfo': {'info_kind': self.kind}}]))
            if command == ['awg', 'show', 'awg0', 'listen-port']:
                return result('585\n')
            if command == ['test', '-f', '/run/ashapp-kernel-ready']:
                return result()
        if args[:2] == ['docker', 'top']:
            if args[3:] != ['-eo', 'pid,comm']:
                return result('Docker requires the PID field.', code=1)
            if self.fail_top:
                return result(code=1)
            return result('PID COMMAND\n42 ' + ('amneziawg-go\n' if self.go or self.process_go else 'tail\n'))
        if args == ['awg', 'genkey']:
            return result(key(1) + '\n')
        if args == ['awg', 'pubkey']:
            return result(key(2) + '\n')
        if args == ['awg', 'genpsk']:
            return result(key(3) + '\n')
        if args == ['modprobe', 'amneziawg']:
            return result()
        raise AssertionError('Unexpected fake command: ' + repr(args))


class SharedSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clients = DockerFixture(self.root)
        self.policy = SimpleNamespace(check_install_policy=Mock(), managed_firewall=Mock(return_value=False))
        self.setup = SimpleNamespace(validate=awg.validate, configure=awg.configure, install_kernel_packages=Mock())
        for name, value in [('DIRECTORY', self.root / 'owned'), ('STATE', self.root / 'state/deployment.json')]:
            target = patch.object(shared, name, value)
            target.start()
            self.addCleanup(target.stop)
        # POSIX ownership has separate native coverage; Windows lacks uid/mode semantics.
        target = patch.object(shared, 'safe_parents')
        target.start()
        self.addCleanup(target.stop)
        target = patch.object(shared, 'read_state', side_effect=lambda: json.loads(shared.STATE.read_text()))
        target.start()
        self.addCleanup(target.stop)
        target = patch.object(shared, 'load_module', side_effect=lambda name: self.setup if name == 'awg_setup' else self.policy)
        target.start()
        self.addCleanup(target.stop)
        target = patch.object(shared.socket, 'socket')
        target.start()
        self.addCleanup(target.stop)
        target = patch.object(shared.time, 'sleep')
        target.start()
        self.addCleanup(target.stop)

    def install(self):
        return shared.install(self.clients, ROOT / 'server')

    def test_real_compatible_paths_single_shared_state_and_no_secret_emission(self):
        result = self.install()
        self.assertEqual(result, {'installed': True, 'source': 'amnezia-awg2', 'awg_port': 585, 'kernel': True})
        self.assertEqual((shared.DIRECTORY / 'data/clientsTable').read_text(), '[]\n')
        config = (shared.DIRECTORY / 'data/awg0.conf').read_text()
        self.assertIn('PrivateKey = ' + key(1), config)
        self.assertNotIn('PostUp', config)
        self.assertEqual((shared.DIRECTORY / 'data/wireguard_psk.key').read_text(), key(3) + '\n')
        self.assertNotIn(key(1), json.dumps(result))
        build = next(args for args, _ in self.clients.calls if args[:2] == ['docker', 'build'])
        self.assertEqual(build[-1], str(shared.DIRECTORY / 'image'))
        self.assertFalse((shared.DIRECTORY / 'image/awg0.conf').exists())
        create = next(args for args, _ in self.clients.calls if args[:2] == ['docker', 'create'])
        self.assertIn('0.0.0.0:585:585/udp', create)
        self.assertNotIn('--privileged', create)
        self.assertNotIn('SYS_MODULE', create)
        self.assertTrue(shared.BASE_IMAGE.endswith('sha256:' + 'c68009d33df3aef4654db72bf1a7880cfa0a631fe866c50d9ae3dd34ddd7c13a'))

    def test_fresh_shared_has_real_awg2_markers_and_nonoverlapping_header_ranges(self):
        self.install()
        config = awg.configure('203.0.113.10', 585, '1.1.1.1', 'eth0', key(1), key(2))[1]
        self.assertNotIn('S3 = ', config)
        self.assertNotIn('S4 = ', config)
        text = (shared.DIRECTORY / 'data/awg0.conf').read_text()
        values = dict(line.split(' = ', 1) for line in text.splitlines() if ' = ' in line)
        self.assertIn('S3', values)
        self.assertIn('S4', values)
        ranges = [tuple(map(int, values['H' + str(index)].split('-'))) for index in range(1, 5)]
        for index, (low, high) in enumerate(ranges):
            self.assertTrue(4 < low < high <= 0xffffffff)
            if index:
                self.assertGreater(low, ranges[index - 1][1])
        self.assertEqual(json.loads(shared.STATE.read_text())['protocol_version'], '2')

    def test_owned_reset_uses_reviewed_identity_and_preserves_changed_or_unknown_files(self):
        self.install()
        with patch.object(shared, 'protected_digest', side_effect=lambda path: hashlib.sha256(path.read_bytes()).hexdigest()):
            plan = shared.owned_removal_plan(self.clients)
            config = shared.DIRECTORY / 'data/awg0.conf'
            config.write_text(config.read_text() + '\n# concurrent edit\n')
            with self.assertRaisesRegex(RuntimeError, 'changed after reset review'):
                shared.remove_owned(self.clients, plan['digest'])
            self.assertIsNotNone(self.clients.container)
            unknown = shared.DIRECTORY / 'data/unrelated'
            unknown.write_text('preserve')
            with self.assertRaisesRegex(RuntimeError, 'Unrecognized shared VPN files'):
                shared.owned_removal_plan(self.clients)
            self.assertEqual(unknown.read_text(), 'preserve')

    def test_owned_reset_removes_only_reviewed_shared_artifacts(self):
        self.install()
        with patch.object(shared, 'protected_digest', side_effect=lambda path: hashlib.sha256(path.read_bytes()).hexdigest()):
            plan = shared.owned_removal_plan(self.clients)
            removed = shared.remove_owned(self.clients, plan['digest'])
        self.assertTrue(removed['removed'])
        self.assertIsNone(self.clients.container)
        self.assertFalse(shared.DIRECTORY.exists())
        self.assertFalse(shared.STATE.exists())
        self.assertFalse(any(args[0] in ('apt', 'apt-get', 'systemctl') for args, _ in self.clients.calls))

    def test_readonly_status_preserves_container_and_has_no_mutating_commands(self):
        self.install()
        self.clients.calls.clear()
        current = shared.shared_status(self.clients)
        self.assertTrue(current['kernel'])
        self.assertFalse(current['userspace'])
        self.assertTrue(current['guard_intact'])
        for args, _ in self.clients.calls:
            self.assertNotIn(args[1], ('start', 'stop', 'restart', 'create', 'build', 'rm'))

    def test_guard_rejects_writable_layer_change_even_while_stopped(self):
        self.install()
        self.clients.container['State']['Running'] = False
        self.clients.extra_diff = 'C /opt/amnezia/start.sh\n'
        status = shared.shared_status(self.clients)
        self.assertFalse(status['guard_intact'])
        with self.assertRaisesRegex(RuntimeError, 'guard changed'):
            shared.control(self.clients, 'start')
        self.assertFalse(self.clients.container['State']['Running'])

    def test_failed_fallback_lookup_does_not_establish_kernel_only_guard(self):
        self.install()
        self.clients.fail_fallback_check = True
        status = shared.shared_status(self.clients)
        self.assertFalse(status['guard_intact'])
        with self.assertRaises(RuntimeError):
            shared.verify(self.clients)

    def test_stop_is_available_after_guard_drift(self):
        self.install()
        self.clients.extra_diff = 'A /usr/bin/amneziawg-go\n'
        stopped = shared.control(self.clients, 'stop')
        self.assertFalse(stopped['running'])
        self.assertFalse(stopped['guard_intact'])

    def test_process_read_failure_clears_an_already_observed_kernel_result(self):
        self.install()
        self.clients.fail_top = True
        current = shared.shared_status(self.clients)
        self.assertFalse(current['kernel'])
        self.assertIn('error', current)
        with self.assertRaises(RuntimeError):
            shared.verify(self.clients)

    def test_official_uploader_artifacts_remain_private_and_compatible_when_stopped(self):
        self.install()
        self.clients.container['State']['Running'] = False
        self.clients.extra_diff = ('C /opt\nC /opt/amnezia\nC /tmp\n'
                                   'A /tmp/Ab0123456789CdEf.tmp\n')
        for temporary_mode in (0o411, 0o1011, 0o2101, 0o600):
            def metadata(_, path, **kwargs):
                folder = path in ('/opt', '/opt/amnezia', '/tmp')
                return dict(uid=0, mode=(0o755 if path == '/opt' else 0o700) if folder else temporary_mode,
                            size=0 if folder else 250, directory=folder, regular=not folder)
            with self.subTest(mode=oct(temporary_mode)), patch.object(shared, 'archive_metadata', side_effect=metadata):
                self.assertTrue(shared.shared_status(self.clients)['guard_intact'])

    def test_uploader_artifacts_refuse_links_foreign_owners_public_data_and_large_files(self):
        state = {'container_id': '1' * 64}
        lines = ['C /tmp', 'A /tmp/Ab0123456789CdEf.tmp']
        for problem in (dict(uid=1000), dict(regular=False), dict(mode=0o644), dict(mode=0o4700),
                        dict(mode=0o2700), dict(size=128 * 1024 + 1)):
            def metadata(_, path, **kwargs):
                folder = path in ('/opt', '/opt/amnezia', '/tmp')
                if folder:
                    return dict(uid=0, mode=0o755 if path == '/opt' else 0o700,
                                size=0, directory=True, regular=False)
                return dict(dict(uid=0, mode=0o600, size=250, directory=False, regular=True), **problem)
            with self.subTest(problem=problem), patch.object(shared, 'archive_metadata', side_effect=metadata):
                self.assertFalse(shared.expected_amnezia_artifacts(state, lines))
        with patch.object(shared, 'archive_metadata') as metadata:
            self.assertFalse(shared.expected_amnezia_artifacts(state, ['A /tmp/unknown.sh']))
            self.assertFalse(shared.expected_amnezia_artifacts(state, ['C /opt/amnezia/start.sh']))
            metadata.assert_not_called()

    def test_archive_metadata_reads_only_a_header_without_extracting_private_bytes(self):
        storage = io.BytesIO()
        entry = tarfile.TarInfo('Ab0123456789CdEf.tmp')
        entry.uid, entry.mode, entry.size = 0, 0o1401, 4096
        with tarfile.open(fileobj=storage, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            archive.addfile(entry, io.BytesIO(b'x' * entry.size))
        stream = io.BytesIO(storage.getvalue())
        process = SimpleNamespace(stdout=stream, kill=Mock())
        opener = Mock()
        opener.return_value.__enter__ = Mock(return_value=process)
        opener.return_value.__exit__ = Mock(return_value=False)
        with patch.object(shared.subprocess, 'Popen', opener), patch.object(shared.threading, 'Timer'):
            metadata = shared.archive_metadata('1' * 64, '/tmp/Ab0123456789CdEf.tmp')
        self.assertEqual(metadata, dict(uid=0, mode=0o1401, size=4096, directory=False, regular=True))
        self.assertLessEqual(stream.tell(), 512)
        process.kill.assert_called_once()
        self.assertEqual(opener.call_args.args[0][-1], '-')

    def test_start_failure_stops_only_the_owned_container(self):
        self.install()
        self.clients.container['State']['Running'] = False
        self.clients.kind = 'wireguard'
        with patch.object(Path, 'is_dir', return_value=True), self.assertRaises(RuntimeError):
            shared.control(self.clients, 'start')
        self.assertFalse(self.clients.container['State']['Running'])
        self.assertEqual([args for args, _ in self.clients.calls if args[:2] == ['docker', 'stop']][-1],
                         ['docker', 'stop', '1' * 64])

    def test_userspace_or_non_awg_interface_never_counts_as_verified_kernel(self):
        self.install()
        self.clients.process_go = True
        observed = shared.shared_status(self.clients)
        self.assertTrue(observed['userspace'])
        with self.assertRaises(RuntimeError):
            shared.verify(self.clients)
        self.clients.process_go = False
        for kind, go in [('wireguard', False), ('amneziawg', True)]:
            with self.subTest(kind=kind, userspace=go):
                self.clients.kind, self.clients.go = kind, go
                with self.assertRaises(RuntimeError):
                    shared.verify(self.clients)

    def test_changed_container_identity_is_preserved(self):
        self.install()
        self.clients.container['Id'] = '9' * 64
        self.clients.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'replaced outside'):
            shared.control(self.clients, 'stop')
        self.assertFalse(any(args[:2] == ['docker', 'stop'] for args, _ in self.clients.calls))

    def test_failed_activation_rolls_back_only_new_vpn_resources(self):
        self.clients.fail_start = True
        with self.assertRaisesRegex(RuntimeError, 'Synthetic activation'):
            self.install()
        self.assertIsNone(self.clients.container)
        self.assertIsNone(self.clients.image)
        self.assertFalse(shared.DIRECTORY.exists())
        self.assertFalse(shared.STATE.exists())
        self.assertTrue(self.clients.AWG_DIR.exists())

    def test_external_configuration_edit_is_retained_on_failed_setup(self):
        def conflict(_):
            (shared.DIRECTORY / 'data/awg0.conf').write_text('external change\n')
            raise RuntimeError('Synthetic conflict.')
        with patch.object(shared, 'wait_ready', side_effect=conflict), self.assertRaisesRegex(RuntimeError, 'recovery files'):
            self.install()
        self.assertEqual((shared.DIRECTORY / 'data/awg0.conf').read_text(), 'external change\n')

    def test_architecture_and_existing_deployment_refuse_before_packages_or_files(self):
        self.clients.arch = 'aarch64'
        with self.assertRaisesRegex(RuntimeError, 'x86_64'):
            self.install()
        self.setup.install_kernel_packages.assert_not_called()
        self.clients.arch = 'x86_64'
        (self.clients.AWG_DIR / 'other.conf').write_text('existing')
        with self.assertRaisesRegex(RuntimeError, 'will not be replaced'):
            self.install()
        self.setup.install_kernel_packages.assert_not_called()
        self.assertFalse(shared.DIRECTORY.exists())

    def test_default_docker_forward_drop_is_accepted_without_bypass_rules(self):
        shared.check_docker_policy(self.clients, self.policy)
        self.policy.check_install_policy.assert_called_once_with(self.clients.run, ('INPUT',))
        self.assertTrue(all(args[:2] == ['iptables', '-S'] for args, _ in self.clients.calls))

    def test_stock_host_and_none_networks_with_null_ipam_are_supported(self):
        self.assertIsNone(self.clients.networks[1]['IPAM']['Config'])
        self.assertIsNone(self.clients.networks[2]['IPAM']['Config'])
        self.assertTrue(self.install()['installed'])

    def test_overlap_is_still_refused_alongside_null_ipam_networks(self):
        self.clients.networks[0]['IPAM']['Config'] = [{'Subnet': '10.66.66.0/24'}]
        with self.assertRaisesRegex(RuntimeError, 'overlaps an existing Docker network'):
            self.install()
        self.setup.install_kernel_packages.assert_not_called()
        self.assertIsNone(self.clients.container)
        self.assertFalse(shared.DIRECTORY.exists())

    def test_foreign_restrictions_in_all_docker_subchains_are_refused(self):
        originals = copy.deepcopy(self.clients.chains)
        for chain, rule in [('FORWARD', '-j DROP'), ('DOCKER-USER', '-s 198.51.100.1/32 -j DROP'),
                            ('DOCKER-FORWARD', '-p udp -j REJECT'), ('DOCKER-CT', '-j FOREIGN'),
                            ('DOCKER-BRIDGE', '-j DROP'), ('DOCKER-INTERNAL', '-j REJECT'),
                            ('DOCKER', '-p udp --dport 585 -j DROP'),
                            ('DOCKER', '-s 198.51.100.1/32 -j ACCEPT')]:
            with self.subTest(chain=chain, rule=rule):
                self.clients.chains = copy.deepcopy(originals)
                self.clients.chains[chain] += '-A ' + chain + ' ' + rule + '\n'
                with self.assertRaises(RuntimeError):
                    shared.check_docker_policy(self.clients, self.policy)

    def test_existing_canonical_publications_remain_untouched(self):
        self.clients.chains['DOCKER'] = ('-N DOCKER\n-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 1080 -j ACCEPT\n'
                                         '-A DOCKER ! -i docker0 -o docker0 -j DROP\n')
        shared.check_docker_policy(self.clients, self.policy)

    def test_owned_docker_protection_requires_verified_ownership(self):
        self.clients.chains['DOCKER-USER'] += '-A DOCKER-USER -j ASHAPP-DKR\n'
        with self.assertRaises(RuntimeError):
            shared.check_docker_policy(self.clients, self.policy)
        self.policy.managed_firewall.return_value = True
        shared.check_docker_policy(self.clients, self.policy)

    def test_startup_uses_kernel_only_and_keeps_keys_out_of_image_context(self):
        self.assertIn('ip link add awg0 type amneziawg', shared.STARTUP)
        self.assertNotIn('awg-quick up', shared.STARTUP)
        self.assertIn('rm -f /usr/bin/amneziawg-go', shared.DOCKERFILE)
        self.assertNotIn('latest', shared.DOCKERFILE)
        bash = Path('C:/Program Files/Git/bin/bash.exe')
        if bash.exists():
            checked = subprocess.run([str(bash), '-n'], input=shared.STARTUP, text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_bundled_helpers_match_sources(self):
        for name in ('amnezia_setup.py', 'awg_setup.py'):
            self.assertEqual((ROOT / 'server' / name).read_bytes(), (ROOT / 'flutter/assets' / name).read_bytes())


if __name__ == '__main__':
    unittest.main()

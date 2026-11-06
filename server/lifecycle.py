#!/usr/bin/env python3
"""Private, secret-free installation ledger, verification and owned removal.

The ledger records choices and action identifiers, never request fields, user
names, keys, client configurations or command output. It is evidence of app
actions, not a substitute for inspecting the running services.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time

STATE = Path('/var/lib/ashapp/lifecycle')
LOCK = Path('/run/ashapp/lifecycle.lock')
CLIENT_LOCK = Path('/run/ashapp/clients.lock')
AWG = Path('/etc/amnezia/amneziawg')
FORWARDING = Path('/etc/sysctl.d/90-ashapp-forwarding.conf')
PING = Path('/usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp')
SOCKS_DIRECTORY = Path('/opt/ashapp/socks5')
BOOL_CHOICES = {'upgrade_packages', 'change_root_password', 'create_admin', 'disable_root',
                'block_ping', 'protect_ssh', 'configure_firewall', 'automatic_updates',
                'disable_password_login', 'generate_ssh_key', 'install_awg', 'install_socks', 'install_vless'}
CHOICES = BOOL_CHOICES | {'awg_deployment', 'awg_port', 'awg_dns', 'socks_port', 'socks_access',
                          'vless_port', 'reality_sni', 'reality_fingerprint', 'ssh_port',
                          'awg_client_count', 'vless_client_count'}
STEPS = {'dependencies', 'upgrade', 'inspect', 'root-password', 'administrator', 'ssh-public-key',
         'ssh-key', 'root-policy', 'ping', 'awg', 'socks', 'vless', 'awg-clients', 'vless-clients',
         'security', 'verify', 'awg-stop', 'socks-stop', 'vless-stop'}
MUTATING = {'dependencies', 'upgrade', 'root-password', 'create-user', 'ssh-config', 'ssh-key',
            'icmp', 'icmp-unblock', 'prepare-awg', 'install-awg-configured', 'install-awg-amnezia',
            'install-vless', 'vless-control', 'socks-install', 'awg-control', 'socks-control',
            'add-client', 'revoke-client', 'rename-client', 'import-client', 'security-stage',
            'security-setup', 'security-confirm', 'security-rollback', 'security-reset-stage', 'reset'}


def module(name):
    spec = importlib.util.spec_from_file_location('ashapp_lifecycle_' + name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if check and result.returncode:
        raise ValueError('Removal command failed: ' + Path(args[0]).name + '. Refresh diagnostics before retrying.')
    return result


def trusted(path, regular=True):
    path = Path(path)
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('Unsafe lifecycle path; no changes were made.')
        if parent.exists():
            metadata = parent.stat()
            if os.name != 'nt' and (metadata.st_uid not in (0, os.geteuid()) or
                                    (metadata.st_mode & 0o022 and not (parent.is_dir() and metadata.st_mode & 0o1000 and metadata.st_uid == 0))):
                raise ValueError('Lifecycle paths need trusted owners and no shared write access.')
    if regular and path.exists() and not path.is_file():
        raise ValueError('A lifecycle file path is occupied by another file type.')
    return path


def file_hash(path):
    path = trusted(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def verify_ping():
    """The known marker alone must not authorize replacing/running edited code."""
    source = Path(__file__).with_name('remote.sh').read_text(encoding='utf-8')
    start = "cat > /usr/share/netfilter-persistent/plugins.d/90-ashapp-icmp <<'PLUGIN'\n"
    if start not in source:
        raise ValueError('The bundled ping policy could not be verified.')
    expected = source.split(start, 1)[1].split('\nPLUGIN\n', 1)[0] + '\n'
    actual = trusted(PING).read_text(encoding='utf-8')
    if actual != expected:
        raise ValueError('The Ashapp ping plugin changed outside the app. It was not executed, replaced or removed.')
    return {'verified': True}


def save(state):
    trusted(STATE, regular=False)
    STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    STATE.chmod(0o700)
    target = trusted(STATE / 'state.json')
    temporary = STATE / ('.state-' + secrets.token_hex(12))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(state, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def load():
    path = trusted(STATE / 'state.json')
    if not path.exists():
        return {'schema': 1, 'status': 'idle', 'run_id': None, 'desired': {}, 'steps': {},
                'events': [], 'components': {}, 'actions': {}}
    if path.stat().st_size > 512 * 1024:
        raise ValueError('Lifecycle state exceeds its safe size limit.')
    state = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(state, dict) or state.get('schema') != 1 or not isinstance(state.get('steps'), dict):
        raise ValueError('Lifecycle state is invalid. Existing services were not changed.')
    return state


def event(state, step, outcome):
    state['events'] = [*state.get('events', []), {'time': int(time.time()), 'step': step, 'state': outcome}][-160:]


def status():
    state = load()
    owned_services = {'awg': False, 'socks': False, 'vless': False}
    for component, name in (('host', 'awg'), ('shared', 'awg'), ('socks', 'socks'), ('vless', 'vless')):
        record = state.get('components', {}).get(component)
        if record:
            try:
                component_evidence(component, record)
                owned_services[name] = True
            except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError):
                pass
    # Internal path hashes and inventory never need to leave the server.
    return {key: state.get(key) for key in ('schema', 'run_id', 'status', 'desired', 'steps', 'events')} | {
        'baseline_available': (module('security_manager').STATE / 'baseline.json').is_file(),
        'reset_available': bool(state.get('components')),
        'owned_services': owned_services,
    }


def choices(value):
    if not isinstance(value, dict) or set(value) - CHOICES:
        raise ValueError('Only non-secret installation choices may be recorded.')
    for key, item in value.items():
        if key in BOOL_CHOICES:
            valid = type(item) is bool
        elif key.endswith('_port'):
            valid = type(item) is int and 1 <= item <= 65535
        elif key.endswith('_count'):
            valid = type(item) is int and 0 <= item <= 200
        elif key == 'awg_deployment':
            valid = item in ('host', 'amnezia')
        elif key == 'socks_access':
            valid = item in ('public', 'private')
        elif key == 'reality_fingerprint':
            valid = item in ('chrome', 'firefox', 'safari', 'edge')
        elif key == 'awg_dns':
            try:
                valid = isinstance(item, str) and ipaddress.ip_address(item).version == 4
            except ValueError:
                valid = False
        else:
            valid = isinstance(item, str) and bool(re.fullmatch(r'[A-Za-z0-9.-]{1,253}', item))
        if not valid:
            raise ValueError('Invalid non-secret installation choice: ' + key + '.')
    return value


def capture_baseline():
    security = module('security_manager')
    security.capture_baseline()


def begin(request):
    if not isinstance(request, dict) or set(request) - {'desired', 'steps', 'resume', 'run_id'}:
        raise ValueError('Invalid installation plan.')
    desired = choices(request.get('desired'))
    if 'resume' in request and type(request['resume']) is not bool:
        raise ValueError('Invalid resume choice.')
    steps = request.get('steps')
    if not isinstance(steps, list) or not steps or len(steps) > len(STEPS) or len(set(steps)) != len(steps) or any(step not in STEPS for step in steps):
        raise ValueError('Invalid installation steps.')
    state = load()
    if request.get('resume') is True:
        if not request.get('run_id') or request['run_id'] != state.get('run_id') or state.get('status') not in ('running', 'failed') or desired != state.get('desired') or set(steps) != set(state['steps']):
            raise ValueError('The interrupted installation changed. Review a new plan instead of resuming it.')
    else:
        state.update(run_id=secrets.token_hex(16), desired=desired,
                     steps={step: {'state': 'waiting', 'updated': int(time.time())} for step in steps})
    capture_baseline()
    state['status'] = 'running'
    event(state, 'installation', 'resumed' if request.get('resume') is True else 'started')
    save(state)
    return {'run_id': state['run_id'], **status()}


def step(run_id, step_id, outcome):
    state = load()
    if run_id != state.get('run_id') or step_id not in state['steps'] or outcome not in ('running', 'done', 'failed'):
        raise ValueError('Installation progress does not match the active plan.')
    previous = state['steps'][step_id]
    state['steps'][step_id] = {'state': outcome, 'updated': int(time.time())}
    if previous.get('credential_state') in ('started', 'committed'):
        state['steps'][step_id]['credential_state'] = previous['credential_state']
    if outcome == 'failed':
        state['status'] = 'failed'
    event(state, step_id, outcome)
    save(state)
    return status()


def record_credential(step_id, outcome):
    """Record only a credential commit boundary, never a username or secret.

    Manual account actions outside the matching active installer step do not
    create misleading resume evidence. Committed evidence is monotonic within
    one run and survives later SSH-verification failure and explicit resume.
    """
    if step_id not in ('administrator', 'root-password') or outcome not in ('started', 'committed'):
        raise ValueError('Invalid credential progress marker.')
    state = load()
    current = state.get('steps', {}).get(step_id)
    if state.get('status') != 'running' or not current or current.get('state') != 'running':
        return
    previous = current.get('credential_state')
    if previous == 'committed' or previous == outcome:
        return
    if outcome == 'committed' and previous != 'started':
        raise ValueError('Credential completion has no matching start marker.')
    current.update(credential_state=outcome, updated=int(time.time()))
    event(state, 'credential-' + step_id, outcome)
    save(state)


def finish(run_id, outcome):
    state = load()
    if run_id != state.get('run_id') or outcome not in ('complete', 'failed'):
        raise ValueError('Installation completion does not match the active plan.')
    if outcome == 'complete' and any(item['state'] != 'done' for item in state['steps'].values()):
        raise ValueError('Installation cannot complete while steps remain unfinished.')
    state['status'] = outcome
    event(state, 'installation', outcome)
    save(state)
    return status()


def inventory():
    socks = False
    if shutil.which('docker'):
        inspected = run(['docker', 'inspect', '--type', 'container', 'amnezia-socks5proxy'], check=False)
        if inspected.returncode == 0:
            rows = json.loads(inspected.stdout)
            if not isinstance(rows, list) or len(rows) != 1 or not re.fullmatch(r'[0-9a-f]{64}', rows[0].get('Id', '')):
                raise ValueError('SOCKS5 identity could not be recorded safely.')
            socks = rows[0]['Id']
    return {'host': (AWG / 'params').exists() or any(AWG.glob('*.conf')),
            'shared': Path('/var/lib/ashapp/amnezia-awg2/deployment.json').exists(),
            'vless': Path('/etc/ashapp/vless').exists(),
            'socks': socks,
            'ping': file_hash(PING), 'forwarding': file_hash(FORWARDING)}


def component_paths(component):
    if component == 'host':
        return [AWG / 'params']
    if component == 'vless':
        vless = module('vless_manager')
        return [vless.UNIT, vless.FIREWALL, vless.BINARY]
    if component == 'socks':
        return [SOCKS_DIRECTORY / 'Dockerfile', SOCKS_DIRECTORY / 'start.sh']
    if component == 'ping':
        return [PING]
    if component == 'forwarding':
        return [FORWARDING]
    return []


def record_action(action, outcome, exit_code=None):
    if action not in MUTATING or outcome not in ('running', 'done', 'failed'):
        return
    state = load()
    if outcome == 'running':
        capture_baseline()
        if action == 'ssh-config':
            module('security_manager').prepare_legacy_ssh()
        state.setdefault('actions', {})[action] = inventory()
    else:
        before = state.setdefault('actions', {}).pop(action, None)
        after = inventory()
        if before is not None:
            for component in ('host', 'shared', 'vless', 'socks', 'ping', 'forwarding'):
                created = not before.get(component) and after.get(component)
                if created:
                    state.setdefault('components', {})[component] = {'created': int(time.time())}
                if component in state.get('components', {}):
                    if not after.get(component):
                        state['components'].pop(component)
                    elif created:
                        # Immutable control files and the selected host configuration
                        # are refreshed only following an app operation, never status.
                        state['components'][component]['files'] = {str(path): file_hash(path) for path in component_paths(component)}
                        if component == 'host':
                            state['components'][component]['control_hash'] = host_control_hash()
                        elif component == 'socks':
                            state['components'][component]['container_id'] = after['socks']
                if component == 'socks' and action == 'socks-install' and outcome == 'done' and component in state.get('components', {}):
                    record = state['components'][component]
                    if created or record.get('container_id') == before.get('socks'):
                        record['container_id'] = after['socks']
        if action == 'ssh-config' and outcome == 'done':
            module('security_manager').record_legacy_ssh()
    event(state, action, outcome)
    if outcome == 'failed' and exit_code is not None and str(exit_code).isdecimal():
        state['events'][-1]['exit_code'] = min(int(exit_code), 255)
    save(state)


def diagnostic_error(error):
    # Exception payloads may contain configuration bytes. Retain type only.
    return 'Inspection failed (' + type(error).__name__ + '); see the action log and check this component locally.'


def host_control_hash():
    path = trusted(AWG / 'awg0.conf')
    text = path.read_text().split('[Peer]', 1)[0].split('### Client ', 1)[0]
    return hashlib.sha256(text.rstrip().encode()).hexdigest()


def service_network_checks(server):
    checks = []
    def check(identity, okay, success, failure):
        checks.append({'id': identity, 'status': 'pass' if okay else 'fail', 'detail': success if okay else failure})
    if server.get('awg') and server.get('kernel'):
        shared = server.get('awg_deployment') == 'amnezia'
        prefix = ['docker', 'exec', 'amnezia-awg2'] if shared else []
        forward = run([*prefix, 'sysctl', '-n', 'net.ipv4.ip_forward'], check=False)
        check('awg-forwarding', forward.returncode == 0 and forward.stdout.strip() == '1',
              'IPv4 forwarding is enabled in the VPN network namespace.', 'VPN IPv4 forwarding is not enabled or could not be read.')
        rules = []
        if shared:
            rules = [[*prefix, 'iptables', '-C', 'FORWARD', '-i', 'awg0', '-o', 'eth0', '-s', '10.66.66.0/24', '-j', 'ACCEPT'],
                     [*prefix, 'iptables', '-C', 'FORWARD', '-i', 'eth0', '-o', 'awg0', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
                     [*prefix, 'iptables', '-t', 'nat', '-C', 'POSTROUTING', '-s', '10.66.66.0/24', '-o', 'eth0', '-j', 'MASQUERADE']]
        else:
            path = AWG / (server.get('interface', 'awg0') + '.conf')
            for line in path.read_text().splitlines():
                if not line.startswith('PostUp = iptables '):
                    continue
                command = shlex.split(line.split('=', 1)[1].strip())
                if '-A' not in command or '--comment' not in command or command[command.index('--comment') + 1] != 'ashapp-awg':
                    continue
                command[command.index('-A')] = '-C'
                rules.append(command)
        check('awg-routing', bool(rules) and all(run(command, check=False).returncode == 0 for command in rules),
              'The VPN forwarding and masquerade rules are present.', 'VPN forwarding/NAT rules are missing or cannot be verified.')
    if server.get('vless'):
        vless = module('vless_manager')
        checked = run([str(vless.BINARY), 'check', '-c', str(vless.DIRECTORY / 'config.json')], check=False)
        check('vless-config', checked.returncode == 0, 'The installed sing-box binary accepts the current VLESS configuration.',
              'The installed sing-box binary rejected the VLESS configuration.')
        listeners = run(['ss', '-H', '-lnt'], check=False)
        active_ports = {int(parts[3].rpartition(':')[2]) for line in listeners.stdout.splitlines()
                        if len(parts := line.split()) >= 4 and parts[3].rpartition(':')[2].isdigit()}
        check('vless-listener', listeners.returncode == 0 and server.get('vless_port') in active_ports,
              'The VLESS TCP listener is bound on the configured port.', 'The configured VLESS TCP port is not listening.')
    return checks


def diagnostics():
    checks, actual = [], {}
    def check(identity, okay, detail, failure=None):
        checks.append({'id': identity, 'status': 'pass' if okay else 'fail', 'detail': detail if okay else failure or detail})
    try:
        ledger = status()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        ledger = None
        checks.append({'id': 'ledger', 'status': 'fail', 'detail': diagnostic_error(error)})
    desired = (ledger or {}).get('desired') or {}
    clients = module('clients')
    try:
        server = clients.status()
        actual['server'] = server
        check('ssh', bool(server.get('ssh')), 'Effective SSH policy is readable.', 'Effective SSH policy is unavailable.')
        owned_services = (ledger or {}).get('owned_services') or {}
        managed_awg = (server.get('awg_host_configured') is True or bool(server.get('interface'))
                       or server.get('awg_deployment') == 'amnezia' or bool(owned_services.get('awg')))
        for external in server.get('external_awg') or []:
            source = external.get('source')
            if server.get('awg_deployment') == 'amnezia' and source == 'amnezia-awg2':
                continue  # The owned shared deployment is checked below.
            if external.get('error'):
                state, detail = 'warn', 'External AmneziaWG could not be fully inspected. Review it in AmneziaVPN; Ashapp did not adopt or change it.'
            elif not external.get('running'):
                state, detail = 'warn', 'External AmneziaWG is stopped. Manage this deployment in AmneziaVPN; Ashapp did not change it.'
            elif external.get('userspace') or external.get('data_plane') == 'userspace':
                state, detail = 'warn', 'External AmneziaWG is running in userspace. It remains managed by AmneziaVPN and was not migrated to kernel mode.'
            elif external.get('kernel') is True:
                state, detail = 'pass', 'External AmneziaWG is running with an observed kernel interface. This does not confer ownership or prove AmneziaVPN GUI adoption.'
            else:
                state, detail = 'warn', 'External AmneziaWG is running; its data plane is not verified. It remains managed by AmneziaVPN.'
            checks.append({'id': 'external-awg-' + str(source), 'status': state,
                           'required': False, 'detail': detail})
        awg_off = desired.get('install_awg') is False and owned_services.get('awg')
        if awg_off:
            check('awg', server.get('awg') is False, 'Owned AmneziaWG is stopped as selected.', 'AmneziaWG is still running although it was switched off.')
        elif desired.get('install_awg') or managed_awg:
            check('awg', server.get('awg') is True and server.get('kernel') is True and not server.get('userspace') and not server.get('awg_error'),
                  'Kernel AmneziaWG is running and its guard is intact.', 'AmneziaWG is stopped, unreadable, userspace, or its kernel guard is invalid.')
            if desired.get('install_awg'):
                check('awg-port', server.get('awg_port') == desired.get('awg_port'), 'AmneziaWG uses the selected UDP port.', 'The AmneziaWG port differs from the selected plan.')
        vless_off = desired.get('install_vless') is False and owned_services.get('vless')
        if vless_off:
            check('vless', server.get('vless') is False, 'Owned VLESS is stopped as selected.', 'VLESS is still running although it was switched off.')
        elif desired.get('install_vless') or server.get('vless_configured'):
            check('vless', server.get('vless') is True and not server.get('vless_error'),
                  'VLESS state, server configuration and running service agree.', 'VLESS is absent, stopped, or its saved configuration is inconsistent.')
            if desired.get('install_vless'):
                check('vless-port', server.get('vless_port') == desired.get('vless_port'), 'VLESS uses the selected TCP port.', 'The VLESS port differs from the selected plan.')
        socks_off = desired.get('install_socks') is False and owned_services.get('socks')
        if socks_off:
            check('socks5', server.get('socks5') is False, 'Owned SOCKS5 is stopped as selected.', 'SOCKS5 is still running although it was switched off.')
        elif desired.get('install_socks') or server.get('socks5_configured'):
            try:
                clients.socks_check()
                check('socks5', True, 'SOCKS5 accepts authentication using its current server credentials.')
            except (OSError, ValueError, RuntimeError) as error:
                checks.append({'id': 'socks5', 'status': 'fail', 'detail': diagnostic_error(error)})
            if desired.get('install_socks'):
                check('socks5-port', server.get('socks5_port') == desired.get('socks_port'), 'SOCKS5 uses the selected port.', 'The SOCKS5 port differs from the selected plan.')
                check('socks5-access', server.get('socks5_access') == desired.get('socks_access'), 'SOCKS5 exposure matches the selected policy.', 'SOCKS5 public/private exposure differs from the selected policy.')
        if 'block_ping' in desired:
            check('ping', server.get('icmp_blocked') == desired['block_ping'], 'Effective IPv4 ping policy matches the selected setting.', 'IPv4 ping filtering differs from the selected setting.')
        if desired.get('disable_root'):
            check('root-login', server.get('ssh', {}).get('permitrootlogin') == 'no', 'Root SSH login is denied.', 'Root SSH login denial is not effective.')
        if desired.get('disable_password_login'):
            ssh = module('security_manager').effective_ssh() or {}
            check('password-login', ssh.get('passwordauthentication') == 'no' and ssh.get('kbdinteractiveauthentication') == 'no',
                  'Password and keyboard-interactive SSH login are denied.', 'Password-based SSH access is not fully denied.')
        if server.get('reboot_required'):
            checks.append({'id': 'reboot', 'status': 'warn', 'detail': 'The operating system requests a reboot.'})
        if server.get('vpn_detection_error'):
            required = managed_awg or any(desired.get(key) for key in ('install_awg', 'install_vless', 'install_socks'))
            checks.append({'id': 'vpn-discovery', 'status': 'fail' if required else 'warn', 'required': required,
                           'detail': 'Existing VPN deployments could not be inspected safely. Review discovery before adding or changing network services.'})
        try:
            checks.extend(service_network_checks(server))
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
            checks.append({'id': 'service-network', 'status': 'fail', 'detail': diagnostic_error(error)})
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        checks.append({'id': 'services', 'status': 'fail', 'detail': diagnostic_error(error)})
    try:
        security = module('security_manager').diagnostics()
        actual['security'] = security
        for identity, key in (('fail2ban', 'protect_ssh'), ('firewall', 'configure_firewall'), ('automatic_updates', 'automatic_updates')):
            data = security.get(identity) or {}
            if key in desired and (desired[key] or data.get('managed')):
                check(identity, data.get('enabled') is desired[key], identity.replace('_', ' ').capitalize() + ' matches the selected setting.',
                      identity.replace('_', ' ').capitalize() + ' differs from the selected setting or could not be verified.')
            if data.get('error'):
                checks.append({'id': identity + '-inspection', 'status': 'fail', 'detail': data['error']})
        if security.get('pending'):
            checks.append({'id': 'security-recovery', 'status': 'warn', 'detail': 'A security change is awaiting confirmation or rollback.'})
        for warning in security.get('warnings', []):
            checks.append({'id': 'security-ownership', 'status': 'fail', 'detail': warning})
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        checks.append({'id': 'security', 'status': 'fail', 'detail': diagnostic_error(error)})
    for key, protocol in (('awg_client_count', 'awg'), ('vless_client_count', 'vless')):
        if not desired.get(key):
            continue
        try:
            rows = clients.list_clients()
            selected = ('vless-reality' if protocol == 'vless' else
                        'amnezia-awg2' if desired.get('awg_deployment') == 'amnezia' else
                        (actual.get('server') or {}).get('interface', 'awg0'))
            count = sum(1 for row in rows.get('clients', []) if row.get('source') == selected)
            check(key, count >= desired[key], 'Requested ' + protocol.upper() + ' client count is present.', 'Fewer clients than requested were found.')
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            checks.append({'id': key, 'status': 'fail', 'detail': diagnostic_error(error)})
    checks.append({'id': 'external-connectivity', 'status': 'warn', 'required': False, 'detail': 'A server-side check cannot prove provider firewall reachability or a remote VPN handshake. Verify with an external client.'})
    return {'checks': checks, 'actual': actual, 'lifecycle': ledger,
            'healthy': not any(item['status'] == 'fail' for item in checks)}


def component_evidence(component, record):
    for name, expected in record.get('files', {}).items():
        if file_hash(Path(name)) != expected:
            raise ValueError('Owned ' + component + ' files changed outside the app. Review them before removal.')
    if component == 'shared':
        evidence = module('amnezia_setup').owned_removal_plan(module('clients'))
        directory = Path('/var/lib/ashapp/clients/amnezia/amnezia-awg2')
        evidence['exports'] = {str(path): file_hash(path) for path in directory.glob('*.conf')}
        return evidence
    if component == 'socks':
        result = run(['docker', 'inspect', '--type', 'container', 'amnezia-socks5proxy'], check=False)
        if result.returncode:
            return {'absent': True}
        row = json.loads(result.stdout)[0]
        if (((row.get('Config') or {}).get('Labels') or {}).get('io.ashapp.managed') != 'socks5-v1'
                or row.get('Mounts') or row.get('Id') != record.get('container_id')):
            raise ValueError('SOCKS5 ownership or mounts are unknown; it was not selected for removal.')
        return {'container_id': row['Id']}
    if component == 'host':
        clients = module('clients')
        params, interface, path, text = clients.settings()
        if interface != 'awg0' or 'ashapp-awg' not in text or path != AWG / 'awg0.conf' or host_control_hash() != record.get('control_hash'):
            raise ValueError('The host VPN is not an owned Ashapp deployment.')
        exports = Path('/var/lib/ashapp/clients')
        return {'interface': interface, 'config': file_hash(path),
                'exports': {str(p): file_hash(p) for p in exports.glob('awg0-client-*.conf')}}
    if component == 'vless':
        vless = module('vless_manager')
        manager = vless.VlessManager()
        manager.load()
        if vless.UNIT.read_text() != vless.unit_text():
            raise ValueError('The VLESS systemd unit changed outside Ashapp.')
        if any(path.name not in {'state.json', 'config.json'} for path in manager.directory.iterdir()):
            raise ValueError('Unrecognized VLESS files or unfinished transactions require manual review before removal.')
        return {'port': manager.load()['port'], 'files': {str(p): file_hash(p) for p in manager.directory.iterdir()}}
    if component == 'ping' and (not PING.exists() or 'ashapp-owned-icmp-v1' not in PING.read_text()):
        raise ValueError('The ping plugin is not owned by Ashapp.')
    return {}


def reset_preview():
    state = load()
    components, evidence = [], {}
    present = inventory()
    for component in ('host', 'shared', 'vless', 'socks', 'ping', 'forwarding'):
        if not present.get(component):
            continue
        record = state.get('components', {}).get(component)
        reason = None
        if not record:
            reason = 'No ownership record exists. This pre-existing component will be preserved.'
        else:
            try:
                evidence[component] = component_evidence(component, record)
            except (OSError, ValueError, KeyError, RuntimeError) as error:
                reason = str(error) if isinstance(error, ValueError) else diagnostic_error(error)
        components.append({'id': component, 'label': {'host': 'Host AmneziaWG', 'shared': 'Experimental shared AmneziaWG', 'vless': 'VLESS Reality', 'socks': 'SOCKS5', 'ping': 'Ashapp ping filtering', 'forwarding': 'Ashapp forwarding setting'}[component],
                           'removable': reason is None, 'reason': reason})
    payload = {'components': components, 'evidence': evidence, 'records': state.get('components', {})}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'digest': digest, 'components': components, 'notice': 'Removes only verified Ashapp-created services and settings. Administrator accounts, passwords, packages, Docker, external services and local exported files are preserved.'}


def reset(expected):
    trusted(CLIENT_LOCK)
    CLIENT_LOCK.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
    with CLIENT_LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return reset_locked(expected)


def reset_locked(expected):
    plan = reset_preview()
    if not secrets.compare_digest(plan['digest'], expected):
        raise ValueError('Removal evidence changed. Review a fresh reset preview.')
    security = module('security_manager')
    if (security.STATE / 'pending.json').exists():
        raise ValueError('Confirm or recover the pending SSH/security change before removing services.')
    removed, warnings = [], []
    state = load()
    for item in plan['components']:
        component = item['id']
        if not item['removable']:
            warnings.append(item['label'] + ': ' + item['reason'])
            continue
        evidence = component_evidence(component, state['components'][component])
        if component == 'host':
            run(['systemctl', 'disable', '--now', 'awg-quick@awg0'])
            if run(['ip', 'link', 'show', 'dev', 'awg0'], check=False).returncode == 0:
                raise ValueError('Host VPN still exists after stop. Configuration was preserved.')
            for path in [*component_paths(component), AWG / 'awg0.conf']:
                path.unlink(missing_ok=True)
            exports = Path('/var/lib/ashapp/clients')
            if exports.is_symlink():
                raise ValueError('Unsafe client export directory; configurations were preserved.')
            for path in exports.glob('awg0-client-*.conf'):
                trusted(path).unlink()
        elif component == 'shared':
            result = module('amnezia_setup').remove_owned(module('clients'), evidence.get('digest'))
            if result and result.get('warning'):
                warnings.append(result['warning'])
            for name, expected_hash in evidence.get('exports', {}).items():
                path = Path(name)
                if file_hash(path) != expected_hash:
                    raise ValueError('The shared VPN was removed, but a changed saved client export was preserved.')
                path.unlink()
        elif component == 'vless':
            vless = module('vless_manager')
            run(['systemctl', 'disable', '--now', vless.SERVICE])
            run([str(vless.FIREWALL), 'flush'])
            for path in vless.DIRECTORY.iterdir():
                trusted(path).unlink()
            vless.DIRECTORY.rmdir()
            for path in component_paths(component):
                trusted(path).unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
        elif component == 'socks':
            if not evidence.get('absent'):
                run(['docker', 'rm', '-f', evidence['container_id']])
            for path in component_paths(component):
                trusted(path).unlink(missing_ok=True)
            if SOCKS_DIRECTORY.exists():
                SOCKS_DIRECTORY.rmdir()
        elif component == 'ping':
            run([str(PING), 'flush'])
            PING.unlink()
        elif component == 'forwarding':
            FORWARDING.unlink()
            # Do not disable runtime forwarding globally: Docker and unrelated
            # networks may still require it. Original runtime baseline follows.
            warnings.append('Removed Ashapp forwarding persistence. Runtime forwarding is retained while other networks may use it.')
        state['components'].pop(component, None)
        event(state, 'reset-' + component, 'done')
        save(state)
        removed.append(component)
    if not state['components']:
        state.update(status='reset', desired={}, steps={})
        save(state)
    return {'removed': removed, 'warnings': warnings, 'lifecycle': status()}


def main():
    if os.geteuid() != 0:
        raise ValueError('Root is required for the lifecycle ledger.')
    os.umask(0o077)
    trusted(LOCK, regular=True)
    LOCK.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        action = sys.argv[1]
        if action == 'record-action':
            record_action(*sys.argv[2:5])
            return
        if action == 'record-credential':
            if len(sys.argv) != 4:
                raise ValueError('Invalid credential progress marker arguments.')
            record_credential(*sys.argv[2:4])
            return
        raw = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError('Lifecycle request exceeds its size limit.')
        fields = raw.decode('utf-8').rstrip('\0').split('\0') if raw else []
        if action == 'lifecycle-status': result = status()
        elif action == 'verify-ping': result = verify_ping()
        elif action == 'lifecycle-begin': result = begin(json.loads(fields[0]))
        elif action == 'lifecycle-step': result = step(*fields)
        elif action == 'lifecycle-finish': result = finish(*fields)
        elif action == 'diagnostics': result = diagnostics()
        elif action == 'reset-preview': result = reset_preview()
        elif action == 'reset': result = reset(fields[0])
        else: raise ValueError('Unknown lifecycle action.')
        print('ASHAPP_JSON:' + json.dumps(result), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError) as error:
        print('ERROR: ' + str(error)[:500], file=sys.stderr)
        sys.exit(1)
    except (OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        print('ERROR: Lifecycle action failed (' + type(error).__name__ + '). Existing unverified files were preserved; inspect diagnostics before retrying.', file=sys.stderr)
        sys.exit(1)

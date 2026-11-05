"""Owned VPS security settings; staged network changes expire without confirmation."""
import base64
import fcntl
import hashlib
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

STATE = Path('/var/lib/ashapp/security')
HELPER = Path('/opt/ashapp/security_manager.py')
FILES = {
    'fail2ban': Path('/etc/fail2ban/jail.d/99-ashapp.local'),
    'firewall': Path('/etc/ashapp/firewall.json'),
    'automatic_updates': Path('/etc/apt/apt.conf.d/99ashapp-security'),
    'ssh': Path('/etc/ssh/ashapp-security.conf'),
}
SSH_MAIN = Path('/etc/ssh/sshd_config')
PLUGIN = Path('/usr/share/netfilter-persistent/plugins.d/92-ashapp-firewall')
RECOVERY = Path('/etc/systemd/system/ashapp-security-recovery.service')
DOCKER_DROPIN = Path('/etc/systemd/system/docker.service.d/90-ashapp-firewall.conf')
FLAGS = {'fail2ban', 'firewall', 'automatic_updates', 'disable_passwords', 'disable_root'}
UNIT = 'ashapp-security-rollback'


def run(args, check=True, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            timeout=2400 if args[0] == 'apt-get' else 30)
    if check and result.returncode:
        # Command output can contain administrative configuration: never echo it.
        raise RuntimeError('Security command failed: ' + args[0] + '. Inspect the service locally.')
    return result


def atomic(path, text, mode=0o600):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Unsafe security file.')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.ashapp-' + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, mode)
        else:
            os.chmod(temporary, mode)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_json(path, default=None):
    if path.is_symlink():
        raise ValueError('Unsafe security state.')
    return json.loads(path.read_text()) if path.exists() else default


def digest(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Unsafe security file.')
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        if parent.is_symlink():
            raise ValueError('Unsafe security directory.')
        parent = parent.parent
    if parent.is_symlink():
        raise ValueError('Unsafe security directory.')
    if os.name != 'nt':
        for item in (parent, path) if path.exists() else (parent,):
            metadata = item.stat()
            if metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
                raise ValueError('Security files and their directories must have a trusted owner and no group/other write access.')
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def owned():
    return read_json(STATE / 'owned.json', {})


def managed_paths():
    return {**FILES, 'plugin': PLUGIN, 'helper': HELPER, 'recovery': RECOVERY, 'docker_dropin': DOCKER_DROPIN}


def check_owned(allow_pending=False):
    known = owned()
    pending = read_json(STATE / 'pending.json', {}) if allow_pending else {}
    for key, path in managed_paths().items():
        actual = digest(path)
        if str(path) in pending.get('expected', {}) and actual in pending['expected'][str(path)]:
            continue
        if key not in known and actual is not None:
            raise ValueError('An unrecognized file uses an Ashapp security path. Review it manually before taking ownership.')
        if key in known and actual != known[key]:
            raise ValueError('An Ashapp security file was edited outside the app. Review it before applying changes.')


def ssh_policy():
    # Reject policy we cannot prove globally, including all expanded Match blocks.
    import glob
    budget = [0, 0]

    def visit(path, stack=()):
        path = Path(path).resolve(strict=True)
        raw = path.read_bytes()
        budget[0] += 1
        budget[1] += len(raw)
        if path in stack or len(stack) >= 16 or budget[0] > 128 or budget[1] > 4 * 1024 * 1024:
            raise ValueError('SSH Include policy exceeds safe review limits.')
        for line in raw.decode('utf-8').splitlines():
            words = shlex.split(line, comments=True)
            if not words:
                continue
            keyword, equal, value = words.pop(0).partition('=')
            if equal and value:
                words.insert(0, value)
            elif not equal and words and words[0].startswith('='):
                value = words.pop(0)[1:]
                if value:
                    words.insert(0, value)
            if keyword.lower() == 'match':
                raise ValueError('Conditional SSH policy requires manual review.')
            if keyword.lower() != 'include':
                continue
            if not words:
                raise ValueError('Empty SSH Include.')
            for pattern in words:
                if any(c in pattern for c in '~$%\\\x00[]{}'):
                    raise ValueError('Unsupported SSH Include syntax.')
                target = str(Path('/etc/ssh') / pattern)
                matches = sorted(glob.glob(target))
                if not matches and not glob.has_magic(target):
                    raise ValueError('Missing SSH Include.')
                for child in matches:
                    visit(child, (*stack, path))
    visit(SSH_MAIN)


def effective_ssh():
    result = run(['/usr/sbin/sshd', '-T'], check=False)
    if result.returncode:
        return None
    return dict(line.split(None, 1) for line in result.stdout.splitlines()
                if line.startswith(('permitrootlogin ', 'passwordauthentication ',
                                    'kbdinteractiveauthentication ', 'pubkeyauthentication ')))


def ssh_ports():
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) != 4 or not connection[3].isdecimal():
        raise ValueError('The SSH connection context is missing.')
    ports = {int(connection[3])}
    for line in run(['/usr/sbin/sshd', '-T']).stdout.splitlines():
        if line.startswith('port ') and line[5:].isdecimal():
            ports.add(int(line[5:]))
    if any(not 1 <= port <= 65535 for port in ports):
        raise ValueError('Invalid SSH port.')
    return sorted(ports)


def listeners():
    result = run(['ss', '-H', '-lntu'], check=False)
    if result.returncode:
        raise ValueError('Listening ports could not be inspected.')
    ports = {'tcp': set(), 'udp': set()}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ports:
            continue
        host, _, value = parts[4].rpartition(':')
        if not value.isdecimal():
            continue
        host = host.strip('[]')
        try:
            if ipaddress.ip_address(host).is_loopback:
                continue
        except ValueError:
            if host != '*':
                continue
        ports[parts[0]].add(int(value))
    return {key: sorted(value) for key, value in ports.items()}


def docker_ports():
    if not shutil.which('docker'):
        return []
    ids = run(['docker', 'ps', '-q']).stdout.split()
    if not ids:
        return []
    rows = json.loads(run(['docker', 'inspect', *ids]).stdout)
    ports = []
    for row in rows:
        for target, bindings in (row.get('NetworkSettings', {}).get('Ports') or {}).items():
            for binding in bindings or []:
                address = binding.get('HostIp', '')
                if address and ipaddress.ip_address(address).is_loopback:
                    continue
                ports.append({'protocol': target.split('/')[-1], 'port': int(binding['HostPort'])})
    return sorted(ports, key=lambda row: (row['protocol'], row['port']))


def active(unit):
    return run(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0


def fail2ban_status():
    result = {'managed': 'fail2ban' in owned(), 'enabled': False, 'banned': [], 'error': None}
    if not shutil.which('fail2ban-client'):
        if result['managed']:
            result.update(enabled=None, error='Fail2ban is missing; the saved policy cannot be verified.')
        return result
    if result['managed'] and re.search(r'(?m)^\[ashapp-sshd\]\nenabled = false$', FILES['fail2ban'].read_text()):
        return result
    status = run(['fail2ban-client', 'status', 'ashapp-sshd'], check=False)
    if status.returncode:
        if result['managed']:
            result['error'] = 'The Ashapp SSH jail could not be verified.'
            result['enabled'] = None
        return result
    result['enabled'] = True
    banned = run(['fail2ban-client', 'get', 'ashapp-sshd', 'banip'], check=False)
    if banned.returncode:
        result['banned'] = None
    else:
        result['banned'] = [str(ipaddress.ip_address(value)) for value in banned.stdout.split()]
    return result


def diagnostics():
    result = {'ssh': effective_ssh(), 'fail2ban': fail2ban_status(),
              'firewall': {'managed': 'firewall' in owned(), 'enabled': None},
              'automatic_updates': {'managed': 'automatic_updates' in owned(), 'enabled': None},
              'reboot_required': Path('/var/run/reboot-required').exists(),
              'pending': (STATE / 'pending.json').exists(), 'warnings': []}
    try:
        check_owned()
    except ValueError as error:
        result['warnings'].append(str(error))
    try:
        result['listeners'] = listeners()
        result['docker_ports'] = docker_ports()
    except (ValueError, RuntimeError, OSError):
        result['listeners'] = None
        result['docker_ports'] = None
    if FILES['firewall'].exists():
        result['firewall']['ports'] = read_json(FILES['firewall'])
        result['firewall'].update(firewall_status(result['firewall']['ports'], result.get('docker_ports')))
    else:
        result['firewall']['enabled'] = False
    config = run(['apt-config', 'dump'], check=False)
    if config.returncode == 0:
        def apt_value(name):
            match = re.search(r'^' + re.escape(name) + r' "([^"\n]*)";', config.stdout, re.M)
            return match[1] if match else None
        periodic = apt_value('APT::Periodic::Unattended-Upgrade')
        result['automatic_updates']['enabled'] = periodic not in (None, '0', 'false', 'False')
        result['automatic_updates']['automatic_reboot'] = apt_value('Unattended-Upgrade::Automatic-Reboot')
    return result


def verify_updates(distro, codename):
    actual = run(['apt-config', 'dump']).stdout
    expected = security_update_text(distro, codename)
    for name, value in [('APT::Periodic::Update-Package-Lists', '1'),
                        ('APT::Periodic::Unattended-Upgrade', '1'),
                        ('Unattended-Upgrade::Automatic-Reboot', 'false')]:
        if not re.search(r'^' + re.escape(name) + ' "' + value + r'";$', actual, re.M):
            raise ValueError('Effective automatic-update policy differs from the selected settings.')
    patterns = re.findall(r'^Unattended-Upgrade::Origins-Pattern:: "([^"\n]*)";', actual, re.M)
    intended = re.findall(r'Origins-Pattern \{ "([^"\n]*)";', expected)
    if patterns != intended or re.search(r'^Unattended-Upgrade::Allowed-Origins:: ', actual, re.M):
        raise ValueError('An external APT configuration overrides the security-only update policy.')


def host_rules(config, tool):
    rules = [['-i', 'lo', '-j', 'ACCEPT'],
             ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
             ['-p', 'ipv6-icmp' if tool == 'ip6tables' else 'icmp', '-j', 'ACCEPT']]
    for protocol in ('tcp', 'udp'):
        rules += [['-p', protocol, '--dport', str(port), '-j', 'ACCEPT'] for port in config[protocol]]
    return [*rules, ['-j', 'DROP']]


def docker_rules(config):
    return ([['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'RETURN']]
            + [['-p', port['protocol'], '-m', 'conntrack', '--ctorigdstport', str(port['port']), '-j', 'RETURN'] for port in config['docker_ports']]
            + [['-m', 'conntrack', '--ctstate', 'DNAT', '-j', 'DROP'], ['-j', 'RETURN']])


def chain_verified(tool, chain, rules):
    current = run([tool, '-S', chain], check=False)
    lines = [line for line in current.stdout.splitlines() if line.startswith('-A ' + chain + ' ')]
    return (current.returncode == 0 and len(lines) == len(rules)
            and all(run([tool, '-C', chain, *rule], check=False).returncode == 0 for rule in rules)
            and shlex.split(lines[-1]) == ['-A', chain, *rules[-1]])


def firewall_status(config, published):
    host = all(run([tool, '-C', 'INPUT', '-j', 'ASHAPP-IN'], check=False).returncode == 0
               and chain_verified(tool, 'ASHAPP-IN', host_rules(config, tool))
               for tool in ('iptables', 'ip6tables'))
    required = bool(config['docker_ports']) or bool(published)
    docker = not required
    if required and published is not None:
        docker = (run(['iptables', '-C', 'DOCKER-USER', '-j', 'ASHAPP-DKR'], check=False).returncode == 0
                  and chain_verified('iptables', 'ASHAPP-DKR', docker_rules(config)))
        if run(['ip6tables', '-S', 'DOCKER-USER'], check=False).returncode == 0:
            docker = (docker and run(['ip6tables', '-C', 'DOCKER-USER', '-j', 'ASHAPP-DKR'], check=False).returncode == 0
                      and chain_verified('ip6tables', 'ASHAPP-DKR', docker_rules(config)))
        configured = {(item['protocol'], item['port']) for item in config['docker_ports']}
        docker = docker and all((item['protocol'], item['port']) in configured for item in published)
    return {'enabled': host and docker if published is not None else None,
            'host_verified': host, 'docker_verified': docker if published is not None else None}


def validate_changes(changes):
    if not isinstance(changes, dict) or not changes or set(changes) - FLAGS:
        raise ValueError('Invalid security choices.')
    if any(type(value) is not bool for value in changes.values()):
        raise ValueError('Invalid security switch value.')


def preview(changes):
    validate_changes(changes)
    check_owned()
    if (STATE / 'pending.json').exists():
        raise ValueError('A security change is pending. Reconnect after its rollback deadline before retrying.')
    if set(changes) & {'disable_passwords', 'disable_root'}:
        ssh_policy()
        if not effective_ssh():
            raise ValueError('SSH policy could not be inspected.')
    ports = listeners()
    ports['tcp'] = sorted(set(ports['tcp']) | set(ssh_ports()))
    published = docker_ports()
    if changes.get('firewall'):
        ufw = run(['ufw', 'status'], check=False).stdout if shutil.which('ufw') else ''
        if ufw.startswith('Status: active') or active('firewalld'):
            raise ValueError('An external firewall is active. Ashapp will not replace it; review it manually.')
        # Native nftables Docker does not have the iptables enforcement hook.
        if published and run(['iptables', '-S', 'DOCKER-USER'], check=False).returncode:
            raise ValueError('Docker firewall backend is unsupported. Existing rules were preserved.')
        for tool in ('iptables', 'ip6tables'):
            policy = run([tool, '-S', 'INPUT'], check=False)
            if policy.returncode:
                raise ValueError('Both IPv4 and IPv6 firewall support are required.')
            if '-P INPUT ACCEPT' not in policy.stdout.splitlines():
                # Appending an allow for every listener to an existing DROP policy
                # could expose a deliberately restricted service or SSH source range.
                raise ValueError('An existing restrictive INPUT policy requires manual firewall review. It will not be widened.')
            if 'firewall' not in owned() and any(
                    run([tool, '-S', chain], check=False).returncode == 0
                    for chain in ('ASHAPP-IN', 'ASHAPP-DKR')):
                raise ValueError('A firewall chain with an Ashapp name already exists. Review ownership manually.')
    snapshot = {str(path): digest(path) for path in [*managed_paths().values(), SSH_MAIN]}
    evidence = {'changes': changes, 'files': snapshot, 'owned': owned(), 'ports': ports,
                'docker_ports': published, 'ssh_ports': ssh_ports()}
    encoded = json.dumps(evidence, sort_keys=True, separators=(',', ':'))
    return {'digest': hashlib.sha256(encoded.encode()).hexdigest(), **evidence,
            'notice': 'Existing listening ports and Docker publications are preserved. Only Ashapp-owned rules are removed when protection is disabled. Network changes roll back unless a fresh SSH connection confirms them within 180 seconds.'}


def firewall_reconcile():
    config = read_json(FILES['firewall'])
    for tool in ('iptables', 'ip6tables'):
        exists = run([tool, '-S', 'ASHAPP-IN'], check=False).returncode == 0
        if not config:
            if exists:
                while run([tool, '-C', 'INPUT', '-j', 'ASHAPP-IN'], check=False).returncode == 0:
                    run([tool, '-D', 'INPUT', '-j', 'ASHAPP-IN'])
                run([tool, '-F', 'ASHAPP-IN']); run([tool, '-X', 'ASHAPP-IN'])
        else:
            rules = host_rules(config, tool)
            lines = ['*filter', ':ASHAPP-IN - [0:0]', '-F ASHAPP-IN']
            lines += ['-A ASHAPP-IN ' + ' '.join(rule) for rule in rules]
            if run([tool, '-C', 'INPUT', '-j', 'ASHAPP-IN'], check=False).returncode:
                # Existing explicit allow/deny rules retain their precedence.
                lines.append('-A INPUT -j ASHAPP-IN')
            # Replace the owned chain in one table transaction, without flushing foreign rules.
            run([tool + '-restore', '--noflush', '--wait', '10'], data='\n'.join([*lines, 'COMMIT', '']))
        docker_hook = run([tool, '-S', 'DOCKER-USER'], check=False).returncode == 0
        docker_chain = run([tool, '-S', 'ASHAPP-DKR'], check=False).returncode == 0
        if not config or not docker_hook:
            if docker_chain:
                if docker_hook:
                    while run([tool, '-C', 'DOCKER-USER', '-j', 'ASHAPP-DKR'], check=False).returncode == 0:
                        run([tool, '-D', 'DOCKER-USER', '-j', 'ASHAPP-DKR'])
                run([tool, '-F', 'ASHAPP-DKR']); run([tool, '-X', 'ASHAPP-DKR'])
            continue
        lines = ['*filter', ':ASHAPP-DKR - [0:0]', '-F ASHAPP-DKR']
        lines += ['-A ASHAPP-DKR ' + ' '.join(rule) for rule in docker_rules(config)]
        if run([tool, '-C', 'DOCKER-USER', '-j', 'ASHAPP-DKR'], check=False).returncode:
            lines.append('-I DOCKER-USER 1 -j ASHAPP-DKR')
        run([tool + '-restore', '--noflush', '--wait', '10'], data='\n'.join([*lines, 'COMMIT', '']))


def reload_ssh():
    run(['/usr/sbin/sshd', '-t'])
    if run(['systemctl', 'reload', 'ssh'], check=False).returncode:
        if run(['systemctl', 'reload', 'sshd'], check=False).returncode:
            if run(['systemctl', 'restart', 'ssh'], check=False).returncode:
                run(['systemctl', 'restart', 'sshd'])


def reload_fail2ban(start=False):
    if shutil.which('fail2ban-client'):
        run(['fail2ban-client', '-t'])
        running = active('fail2ban')
        if start:
            boot = run(['systemctl', 'is-enabled', 'fail2ban.service'], check=False).stdout.strip()
            if boot not in ('enabled', 'disabled'):
                raise ValueError('Nonstandard Fail2ban startup policy requires manual review; it will not be converted or unmasked.')
            run(['systemctl', 'enable', '--now', 'fail2ban'])
        if running:
            run(['fail2ban-client', 'reload'])


def security_update_text(distro, codename):
    if distro not in ('ubuntu', 'debian') or not re.fullmatch('[a-z]+', codename):
        raise ValueError('Unsupported security-update distribution.')
    origin = (f'origin=Ubuntu,archive={codename}-security' if distro == 'ubuntu'
              else f'origin=Debian,codename={codename}-security,label=Debian-Security')
    return ('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
            '#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\n'
            f'Unattended-Upgrade::Origins-Pattern {{ "{origin}"; }};\n'
            'Unattended-Upgrade::Automatic-Reboot "false";\n')


def verify_fail2ban():
    for name, expected in [('maxretry', '5'), ('findtime', '600'), ('bantime', '900')]:
        if run(['fail2ban-client', 'get', 'ashapp-sshd', name]).stdout.strip() != expected:
            raise ValueError('Effective Fail2ban settings differ from the selected policy.')
    if not run(['fail2ban-client', 'get', 'ashapp-sshd', 'journalmatch']).stdout.strip():
        raise ValueError('Fail2ban journal matching is not configured.')
    # Use documentation-only addresses to check both installed packet-filter actions.
    # Never unban a pre-existing address or generate failed SSH logins from the administrator.
    already = {str(ipaddress.ip_address(value)) for value in
               run(['fail2ban-client', 'get', 'ashapp-sshd', 'banip']).stdout.split()}
    for tool, address in [('iptables', '192.0.2.254'), ('ip6tables', '2001:db8::fffe')]:
        if address in already:
            continue
        try:
            run(['fail2ban-client', 'set', 'ashapp-sshd', 'banip', address])
            blocked = False
            for attempt in range(10):
                installed = run([tool, '-S', 'f2b-ashapp-sshd'], check=False).stdout
                for line in installed.splitlines():
                    words = shlex.split(line)
                    if '-s' in words and '-j' in words:
                        source = words[words.index('-s') + 1]
                        blocked |= (ipaddress.ip_address(address) in ipaddress.ip_network(source, strict=False)
                                    and words[words.index('-j') + 1] in ('DROP', 'REJECT'))
                if blocked:
                    break
                time.sleep(0.2)
            if not blocked:
                raise ValueError('Fail2ban packet-filter action could not be verified.')
        finally:
            run(['fail2ban-client', 'set', 'ashapp-sshd', 'unbanip', address])


def pending_save(pending):
    atomic(STATE / 'pending.json', json.dumps(pending))


def stage(changes, expected):
    plan = preview(changes)
    if plan['digest'] != expected:
        raise ValueError('Server settings changed after preview. Review the new plan.')
    fresh_fail2ban = not shutil.which('fail2ban-client')
    if changes.get('fail2ban'):
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=180', 'update'])
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=180', 'install', '-y', 'fail2ban', 'python3-systemd'])
    if changes.get('automatic_updates'):
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=180', 'install', '-y', 'unattended-upgrades'])
    if changes.get('firewall') and not shutil.which('netfilter-persistent'):
        run(['debconf-set-selections'], data='iptables-persistent iptables-persistent/autosave_v4 boolean false\n'
            'iptables-persistent iptables-persistent/autosave_v6 boolean false\n')
        run(['apt-get', '-o', 'DPkg::Lock::Timeout=180', 'install', '-y', 'iptables-persistent'])
    if preview(changes)['digest'] != expected:
        raise ValueError('Server policy changed while installing dependencies. Review a fresh preview.')
    HELPER.parent.mkdir(parents=True, exist_ok=True)
    atomic(HELPER, Path(__file__).read_text(), 0o700)
    atomic(RECOVERY, '[Unit]\nDescription=Recover an unconfirmed Ashapp security change\n'
           'After=network.target ssh.service sshd.service netfilter-persistent.service fail2ban.service docker.service\n'
           'ConditionPathExists=/var/lib/ashapp/security/pending.json\n[Service]\nType=oneshot\n'
           'ExecStart=/usr/bin/python3 /opt/ashapp/security_manager.py recover\n'
           '[Install]\nWantedBy=multi-user.target\n', 0o644)
    support = owned()
    support.update(helper=digest(HELPER), recovery=digest(RECOVERY))
    atomic(STATE / 'owned.json', json.dumps(support))
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'ashapp-security-recovery.service'])
    token = secrets.token_hex(24)
    paths = [*managed_paths().values(), SSH_MAIN, STATE / 'owned.json']
    pending = {'token': token, 'unit': UNIT + '-' + token[:16], 'expires': time.time() + 180,
               'connection': os.environ.get('SSH_CONNECTION'), 'changes': changes,
               'before': {str(p): {'data': base64.b64encode(p.read_bytes()).decode(), 'mode': p.stat().st_mode & 0o777}
                          if p.exists() else None for p in paths},
               'expected': {}, 'started': False,
               'units': {unit: {'active': active(unit),
                                'enabled': run(['systemctl', 'is-enabled', unit], check=False).stdout.strip()}
                         for unit in (['fail2ban.service'] if 'fail2ban' in changes else []) +
                                     (['apt-daily.timer', 'apt-daily-upgrade.timer'] if changes.get('automatic_updates') else []) +
                                     (['netfilter-persistent.service'] if changes.get('firewall') else [])}}
    pending_save(pending)

    def write(path, text=None, mode=0o600):
        name = str(path)
        previous = digest(path)
        original = pending['before'][name]
        before_hash = hashlib.sha256(base64.b64decode(original['data'])).hexdigest() if original else None
        if previous not in pending['expected'].get(name, [before_hash]):
            raise ValueError('A security file changed before it could be updated.')
        after = hashlib.sha256(text.encode()).hexdigest() if text is not None else None
        # Either side of atomic replace is recoverable after a disconnect/crash.
        pending['expected'][name] = [previous, after]
        pending_save(pending)
        if text is None:
            path.unlink(missing_ok=True)
        else:
            atomic(path, text, mode)
        pending['expected'][name] = [after]
        pending_save(pending)
    try:
        run(['systemd-run', '--unit=' + pending['unit'], '--collect', '--on-active=180s', '/usr/bin/python3', str(HELPER), 'rollback', token])
        pending['started'] = True
        pending_save(pending)
        if 'fail2ban' in changes:
            previous = FILES['fail2ban'].read_text() if FILES['fail2ban'].exists() else ''
            # A fresh package may enable its file-log SSH jail even on journal-only VPS images.
            # Only that newly installed default is superseded; existing installations keep their jails.
            default = '[sshd]\nenabled = false\n\n' if fresh_fail2ban or previous.startswith('[sshd]') else ''
            write(FILES['fail2ban'], default + '[ashapp-sshd]\nenabled = ' + str(changes['fail2ban']).lower() +
                  '\nfilter = sshd\nbackend = systemd\nport = ' + ','.join(map(str, plan['ssh_ports'])) +
                  '\nmaxretry = 5\nfindtime = 10m\nbantime = 15m\nbanaction = iptables-multiport\n')
            reload_fail2ban(start=changes['fail2ban'])
            if changes['fail2ban']:
                verify_fail2ban()
        if 'automatic_updates' in changes:
            if changes['automatic_updates']:
                release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
                distro = release.get('ID', '').strip('"')
                codename = release.get('VERSION_CODENAME', '').strip('"')
                write(FILES['automatic_updates'], security_update_text(distro, codename), 0o644)
                verify_updates(distro, codename)
                run(['systemctl', 'enable', '--now', 'apt-daily.timer', 'apt-daily-upgrade.timer'])
            else:
                write(FILES['automatic_updates'])
        if set(changes) & {'disable_passwords', 'disable_root'}:
            text = FILES['ssh'].read_text() if FILES['ssh'].exists() else ''
            values = dict(line.split(None, 1) for line in text.splitlines() if line.strip())
            if 'disable_passwords' in changes:
                values.update(PasswordAuthentication='no' if changes['disable_passwords'] else 'yes', PubkeyAuthentication='yes')
                if changes['disable_passwords']:
                    values['KbdInteractiveAuthentication'] = 'no'
                else:
                    values.pop('KbdInteractiveAuthentication', None)
            if 'disable_root' in changes:
                values['PermitRootLogin'] = 'no' if changes['disable_root'] else 'yes'
            write(FILES['ssh'], ''.join(f'{k} {v}\n' for k, v in values.items()))
            include = 'Include /etc/ssh/ashapp-security.conf\n'
            write(SSH_MAIN, include + SSH_MAIN.read_text().replace(include, ''))
            reload_ssh()
            effective = effective_ssh()
            if changes.get('disable_passwords') and any(effective.get(key) != 'no' for key in ('passwordauthentication', 'kbdinteractiveauthentication')):
                raise ValueError('Password SSH denial could not be verified.')
            if changes.get('disable_root') and effective.get('permitrootlogin') != 'no':
                raise ValueError('Root SSH denial could not be verified.')
        if 'firewall' in changes:
            if changes['firewall']:
                # Shared with the unprivileged VLESS service's config directory.
                # Set traversal only on a directory created by this operation.
                if not FILES['firewall'].parent.exists():
                    FILES['firewall'].parent.mkdir(mode=0o755)
                    FILES['firewall'].parent.chmod(0o755)
                write(FILES['firewall'], json.dumps({**plan['ports'], 'docker_ports': plan['docker_ports']}))
                write(PLUGIN, '#!/bin/sh\ncase "$1" in start|restart|reload) exec /usr/bin/python3 /opt/ashapp/security_manager.py firewall-restore ;; esac\n', 0o755)
                write(DOCKER_DROPIN, '[Service]\nExecStartPost=/usr/bin/python3 /opt/ashapp/security_manager.py firewall-restore\n', 0o644)
            else:
                write(FILES['firewall'])
                write(PLUGIN)
                write(DOCKER_DROPIN)
            run(['systemctl', 'daemon-reload'])
            firewall_reconcile()
            if changes['firewall']:
                run(['systemctl', 'enable', 'netfilter-persistent'])
        check_owned(allow_pending=True)
        updated = {key: value for key, path in managed_paths().items() if (value := digest(path)) is not None}
        write(STATE / 'owned.json', json.dumps(updated))
        return {'token': token, 'rollback_seconds': 180}
    except BaseException:
        # On a regular failure, restore immediately; the timer also handles disconnects.
        rollback(token)
        raise


def rollback(token):
    pending = read_json(STATE / 'pending.json')
    if not pending or not secrets.compare_digest(pending['token'], token):
        return {'rolled_back': False}
    if pending.get('expected'):
        for name, expected in pending['expected'].items():
            if digest(Path(name)) not in expected:
                raise ValueError('Security recovery needs manual review: a file changed after staging.')
    for name in pending['expected']:
        encoded = pending['before'][name]
        path = Path(name)
        if encoded is None:
            path.unlink(missing_ok=True)
        else:
            atomic(path, base64.b64decode(encoded['data']).decode(), encoded['mode'])
    if 'firewall' in pending['changes']:
        run(['systemctl', 'daemon-reload'])
        firewall_reconcile()
    if set(pending['changes']) & {'disable_passwords', 'disable_root'}:
        reload_ssh()
    if 'fail2ban' in pending['changes']:
        reload_fail2ban()
    for unit, previous in pending.get('units', {}).items():
        if not previous['active']:
            run(['systemctl', 'stop', unit])
        elif not active(unit):
            run(['systemctl', 'start', unit])
        if previous['enabled'] == 'disabled':
            run(['systemctl', 'disable', unit])
    (STATE / 'pending.json').unlink()
    run(['systemctl', 'stop', pending['unit'] + '.timer'], check=False)
    return {'rolled_back': True}


def confirm(token):
    pending = read_json(STATE / 'pending.json')
    if not pending or not secrets.compare_digest(pending['token'], token) or time.time() >= pending['expires']:
        raise ValueError('The security change expired. Refresh after rollback.')
    if not os.environ.get('SSH_CONNECTION') or pending['connection'] == os.environ['SSH_CONNECTION']:
        raise ValueError('A fresh SSH connection must confirm security changes.')
    for name, expected in pending['expected'].items():
        if digest(Path(name)) not in expected:
            raise ValueError('Security files changed before confirmation.')
    run(['systemctl', 'stop', pending['unit'] + '.timer'])
    (STATE / 'pending.json').unlink()
    return {'confirmed': True}


def acquire_lock(lock, action):
    recovery = action in ('rollback', 'recover', 'security-rollback', 'firewall-restore')
    fcntl.flock(lock, fcntl.LOCK_EX if recovery else fcntl.LOCK_EX | fcntl.LOCK_NB)


def main():
    if os.geteuid() != 0:
        raise ValueError('Root is required.')
    os.umask(0o077)
    os.environ['LC_ALL'] = 'C'
    for directory in (STATE, Path('/run/ashapp')):
        if directory.is_symlink():
            raise ValueError('Unsafe security state directory.')
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.stat().st_uid != 0:
            raise ValueError('Unsafe security state owner.')
        directory.chmod(0o700)
    with (Path('/run/ashapp') / 'security.lock').open('a') as lock:
        action = sys.argv[1]
        acquire_lock(lock, action)
        fields = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(fields) > 1024 * 1024:
            raise ValueError('Security request is too large.')
        args = fields.decode().rstrip('\x00').split('\x00') if fields else []
        if action == 'security-status':
            result = diagnostics()
        elif action == 'security-preview':
            result = preview(json.loads(args[0]))
        elif action == 'security-stage':
            result = stage(json.loads(args[0]), args[1])
        elif action == 'security-confirm':
            result = confirm(args[0])
        elif action == 'security-rollback':
            result = rollback(args[0])
        elif action == 'rollback':
            result = rollback(sys.argv[2])
        elif action == 'recover':
            pending = read_json(STATE / 'pending.json')
            result = rollback(pending['token']) if pending else {'rolled_back': False}
        elif action == 'firewall-restore':
            check_owned(allow_pending=True)
            firewall_reconcile(); result = {'restored': True}
        elif action == 'security-unban':
            address = str(ipaddress.ip_address(args[0]))
            run(['fail2ban-client', 'set', 'ashapp-sshd', 'unbanip', address])
            result = diagnostics()
        else:
            raise ValueError('Unknown security action.')
        print('ASHAPP_JSON:' + json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print('ERROR: ' + str(error)[:500], file=sys.stderr)
        sys.exit(1)
    except (RuntimeError, OSError, IndexError, KeyError, subprocess.SubprocessError):
        print('ERROR: Security operation failed. Existing external configuration was not intentionally replaced; inspect security status and recovery files before retrying.', file=sys.stderr)
        sys.exit(1)

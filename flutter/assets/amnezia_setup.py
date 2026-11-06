#!/usr/bin/env python3
"""Opt-in AmneziaVPN-compatible deployment; its data plane stays kernel-only.

The official amneziavpn/amneziawg-go:3.1.20260828 Linux/amd64 image was
resolved through registry-1.docker.io on 2026-11-06. Pin the platform digest,
not latest or an unverified tag. The derived image deletes the Go fallback
and starts a kernel interface directly. A later reinstall by AmneziaVPN can
replace this guard; read-only status reports that drift, never hides it.

Compatibility paths/schema follow amnezia-client commit
de93650a90739b87bb47a632872ea9d0adc9412f. Both managers edit the same real
configuration and clientsTable, not synthetic discovery metadata.
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

SOURCE = 'amnezia-awg2'
IMAGE = 'ashapp-amnezia-awg2-kernel:3.1.20260828-r1'
BASE_IMAGE = 'amneziavpn/amneziawg-go@sha256:c68009d33df3aef4654db72bf1a7880cfa0a631fe866c50d9ae3dd34ddd7c13a'
OWNER = 'amneziawg-kernel-v1'
DIRECTORY = Path('/opt/ashapp/amnezia-awg2')
STATE = Path('/var/lib/ashapp/amnezia-awg2/deployment.json')
SUBNET = ipaddress.ip_network('10.66.66.0/24')
CONTAINER_DATA = '/opt/amnezia/awg'
STARTUP = r'''#!/bin/bash
set -euo pipefail
umask 077
config=/opt/amnezia/awg/awg0.conf
[[ -f "$config" && ! -L "$config" ]] || exit 70
! command -v amneziawg-go >/dev/null 2>&1 || exit 72
ip link add awg0 type amneziawg
trap 'ip link delete awg0 >/dev/null 2>&1 || true' EXIT
[[ -d /sys/module/amneziawg ]] || exit 71
address="$(awk -F= '/^[[:space:]]*Address[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2}' "$config")"
[[ "$address" =~ ^[0-9.]+/[0-9]+$ ]] || exit 73
awk 'BEGIN{s=0} /^\[Interface\]/{s=1} /^\[Peer\]/{s=0}
     s && /^[[:space:]]*(Address|DNS|MTU|Table|SaveConfig|PreUp|PostUp|PreDown|PostDown)[[:space:]]*=/ {next}
     {print}' "$config" | awg setconf awg0 /dev/stdin
ip address add "$address" dev awg0
ip link set mtu 1376 up dev awg0
[[ "$(cat /proc/sys/net/ipv4/ip_forward)" == 1 ]] || exit 74
ip -d -j link show dev awg0 | grep -q '"info_kind":"amneziawg"\|"info_kind": "amneziawg"' || exit 75
iptables -A FORWARD -i awg0 -o eth0 -s 10.66.66.0/24 -j ACCEPT
iptables -A FORWARD -i eth0 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
: > /run/ashapp-kernel-ready
trap - EXIT
exec tail -f /dev/null
'''
DOCKERFILE = (f'FROM {BASE_IMAGE}\n'
              f'LABEL io.ashapp.managed="{OWNER}"\n'
              'RUN rm -f /usr/bin/amneziawg-go /usr/local/bin/amneziawg-go && '
              '! command -v amneziawg-go && mkdir -p /opt/amnezia/awg && '
              'chmod 0700 /opt/amnezia /tmp && '
              'test -x /bin/bash && command -v ip && command -v iptables && command -v awg\n'
              'COPY start.sh /opt/amnezia/start.sh\n'
              'RUN chmod 0700 /opt/amnezia/start.sh\n'
              'ENTRYPOINT ["/bin/bash", "/opt/amnezia/start.sh"]\n')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def configure_shared(setup, host, port, dns, private, public):
    """A fresh AWG2 configuration, recognized from its real protocol parameters.

    Keep the host installer generation unchanged. The official Amnezia parser
    infers AWG2 from S3/S4 or header ranges, not the container name. The loaded
    module must accept this configuration during kernel-only activation.
    """
    _, config = setup.configure(host, port, dns, 'eth0', private, public)
    config = ''.join(line + '\n' for line in config.splitlines() if not line.startswith(('PostUp', 'PostDown')))
    for index in range(4):
        # One disjoint quarter of uint32 for each message kind, avoiding the
        # un-obfuscated WireGuard type values and a wrap at the upper bound.
        start = index * (1 << 30) + 5 + secrets.randbelow((1 << 30) - 1030)
        end = start + 16 + secrets.randbelow(1000)
        config = re.sub(rf'(?m)^H{index + 1} = .+$', f'H{index + 1} = {start}-{end}', config)
    config += f'S3 = {secrets.randbelow(49) + 1}\nS4 = {secrets.randbelow(17) + 1}\n'
    return config


def load_module(name):
    spec = importlib.util.spec_from_file_location('ashapp_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_parents(path):
    """Refuse linked/non-root/writable ancestors, including absent leaf paths."""
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise RuntimeError('Unsafe shared-management storage path.')
        if parent.exists():
            details = parent.stat()
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
                raise RuntimeError('Shared-management storage must be root-owned and protected.')


def inspect(clients):
    result = clients.run(['docker', 'inspect', '--type', 'container', SOURCE], check=False)
    if result.returncode:
        raise RuntimeError('The shared AmneziaWG container is unavailable.')
    values = json.loads(result.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise RuntimeError('The shared container identity is ambiguous.')
    return values[0]


def read_state():
    safe_parents(STATE.parent)
    if STATE.is_symlink() or not STATE.is_file():
        raise RuntimeError('The shared deployment record is unavailable.')
    details = STATE.stat()
    if details.st_uid != 0 or details.st_mode & 0o077:
        raise RuntimeError('The shared deployment record is not protected.')
    value = json.loads(STATE.read_text())
    if (not isinstance(value, dict) or value.get('schema') != 1 or value.get('source') != SOURCE
            or not re.fullmatch(r'[a-f0-9]{64}', str(value.get('container_id', '')))
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', str(value.get('image_id', '')))
            or not isinstance(value.get('port'), int) or not 1 <= value['port'] <= 65535):
        raise RuntimeError('The shared deployment record is invalid.')
    return value


def identity(clients, state):
    current = inspect(clients)
    if (current.get('Id') != state['container_id']
            or current.get('Config', {}).get('Labels', {}).get('io.ashapp.managed') != OWNER):
        raise RuntimeError('The shared container was replaced outside Ashapp. Review it before continuing.')
    mounts = current.get('Mounts', [])
    if not any(m.get('Type') == 'bind' and m.get('Source') == str(DIRECTORY / 'data')
               and m.get('Destination') == CONTAINER_DATA and m.get('RW') is True for m in mounts):
        raise RuntimeError('Shared VPN storage no longer matches the deployment record.')
    bindings = current.get('HostConfig', {}).get('PortBindings', {})
    if bindings != {str(state['port']) + '/udp': [{'HostIp': '0.0.0.0', 'HostPort': str(state['port'])}]}:
        raise RuntimeError('The shared public UDP listener no longer matches its record.')
    return current


def archive_metadata(container, path, timeout=10):
    """Read one bounded TAR header, including for a stopped container.

    Docker cp's stdout is binary and must never pass through the text/logging
    command adapter. No files are extracted or retained and no private file
    body is parsed. A watchdog kills only this newly spawned CLI reader.
    """
    if not re.fullmatch('[a-f0-9]{64}', container):
        raise RuntimeError('Invalid shared container identity.')
    class HeaderReader:
        def __init__(self, stream):
            self.stream, self.remaining = stream, 16 * 1024

        def read(self, amount):
            if amount < 0 or amount > self.remaining:
                raise RuntimeError('The Docker archive header exceeded its limit.')
            value = self.stream.read(amount)
            self.remaining -= len(value)
            return value

    with subprocess.Popen(['docker', 'cp', container + ':' + path, '-'],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        def stop():
            try:
                process.kill()
            except OSError:
                pass
        timer = threading.Timer(timeout, stop)
        timer.daemon = True
        timer.start()
        try:
            with tarfile.open(fileobj=HeaderReader(process.stdout), mode='r|', bufsize=512) as archive:
                entry = archive.next()
                if entry is None:
                    raise RuntimeError('Docker path metadata is unavailable.')
                return dict(uid=entry.uid, mode=entry.mode, size=entry.size,
                            directory=entry.isdir(), regular=entry.isreg())
        except (tarfile.TarError, OSError, EOFError):
            raise RuntimeError('Docker path metadata could not be verified.') from None
        finally:
            timer.cancel()
            stop()


def expected_amnezia_artifacts(state, lines):
    """Accept only private artifacts left by the pinned official SSH uploader.

    Its SCP implementation passes open() flags as mode bits, so append files
    may be 0411 (Windows), 01011 (macOS), or 02101 (Linux), not 0600.
    Private 0700 parents are mandatory;
    group/other read or write, links, unbounded data and unknown paths fail.
    """
    if not lines:
        return True
    files = []
    for line in lines:
        if line in ('C /opt', 'C /opt/amnezia', 'C /tmp'):
            continue
        match = re.fullmatch(r'A (/tmp/[A-Za-z0-9]{16}\.tmp)', line)
        if not match:
            return False
        files.append(match[1])
    if len(files) > 256:
        return False
    deadline = time.monotonic() + 20
    for path in ('/opt', '/opt/amnezia', '/tmp', *files):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        value = archive_metadata(state['container_id'], path, timeout=min(remaining, 10))
        if value['uid'] != 0:
            return False
        if path in ('/opt', '/opt/amnezia', '/tmp'):
            if not value['directory'] or value['mode'] & 0o022:
                return False
            if path != '/opt' and value['mode'] & 0o777 != 0o700:
                return False
        elif (not value['regular'] or value['size'] > 128 * 1024 or value['size'] < 0
              or value['mode'] & 0o4066 or (value['mode'] & 0o2000 and value['mode'] != 0o2101)):
            return False
    return True


def guard_intact(clients, state, current):
    if current.get('Image') != state['image_id'] or state.get('startup_sha256') != digest(STARTUP):
        return False
    safe_parents(DIRECTORY / 'image')
    safe_parents(DIRECTORY / 'data')
    for name, expected in (('image/start.sh', STARTUP), ('image/Dockerfile', DOCKERFILE)):
        path = DIRECTORY / name
        if path.is_symlink() or not path.is_file() or path.read_text() != expected:
            return False
    changes = clients.run(['docker', 'diff', state['container_id']], check=False)
    allowed_changes = {'C /run', 'A /run/xtables.lock', 'C /var', 'C /var/run',
                       'A /var/run/xtables.lock', 'A /run/ashapp-kernel-ready'}
    extras = [line.strip() for line in changes.stdout.splitlines() if line.strip() not in allowed_changes]
    if changes.returncode or not expected_amnezia_artifacts(state, extras):
        return False
    if current.get('State', {}).get('Running'):
        result = clients.run(['docker', 'exec', SOURCE, 'sha256sum', '/opt/amnezia/start.sh'], check=False)
        if result.returncode or result.stdout.split()[0:1] != [digest(STARTUP)]:
            return False
        # BusyBox returns 127 for an absent command, while other shells use 1.
        # Normalize absence inside the shell; Docker/channel errors still fail closed.
        fallback = clients.run(['docker', 'exec', SOURCE, 'sh', '-c',
                                '! command -v amneziawg-go >/dev/null 2>&1'], check=False)
        if fallback.returncode != 0:
            return False
    return True


def shared_status(clients):
    result = dict(configured=STATE.exists() or STATE.is_symlink(), running=False, kernel=False,
                  userspace=False, port=None, guard_intact=False, source=SOURCE)
    if not result['configured']:
        return result
    phase = 'deployment record'
    try:
        state = read_state()
        result['port'] = state['port']
        phase = 'container identity'
        current = identity(clients, state)
        result['running'] = current.get('State', {}).get('Running') is True
        phase = 'kernel-only guard'
        result['guard_intact'] = guard_intact(clients, state, current)
        if result['running']:
            phase = 'kernel interface'
            links = clients.run(['docker', 'exec', SOURCE, 'ip', '-d', '-j', 'link', 'show', 'dev', 'awg0'], check=False)
            entries = json.loads(links.stdout) if links.returncode == 0 else []
            port = clients.run(['docker', 'exec', SOURCE, 'awg', 'show', 'awg0', 'listen-port'], check=False)
            ready = clients.run(['docker', 'exec', SOURCE, 'test', '-f', '/run/ashapp-kernel-ready'], check=False)
            result['kernel'] = (any(v.get('linkinfo', {}).get('info_kind') == 'amneziawg'
                                    and 'UP' in v.get('flags', []) for v in entries)
                                and port.returncode == 0 and port.stdout.strip() == str(state['port'])
                                and ready.returncode == 0)
            phase = 'process inspection'
            # Docker maps host PIDs into the container and requires a PID column.
            processes = clients.run(['docker', 'top', SOURCE, '-eo', 'pid,comm'], check=False)
            if processes.returncode:
                raise RuntimeError('The VPN process list could not be verified.')
            rows = [line.split(None, 1) for line in processes.stdout.splitlines()]
            rows = [parts for parts in rows if len(parts) == 2 and parts[0].isdecimal()]
            if not rows:
                raise RuntimeError('The VPN process list could not be verified.')
            result['userspace'] = any(parts[1].strip() == 'amneziawg-go' for parts in rows)
        if not result['guard_intact']:
            result['error'] = 'The kernel-only guard changed outside Ashapp. Do not reinstall or update this VPN in AmneziaVPN.'
        elif result['running'] and (not result['kernel'] or result['userspace']):
            result['error'] = 'The shared VPN is not verified in kernel-only mode.'
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        result['kernel'] = False
        result['error'] = f'The shared VPN {phase} check failed ({type(error).__name__}). Review the deployment.'
    return result


def verify(clients):
    result = shared_status(clients)
    if not (result['configured'] and result['running'] and result['guard_intact']
            and result['kernel'] and not result['userspace'] and not result.get('error')):
        raise RuntimeError(result.get('error', 'The shared kernel VPN is stopped or unavailable.'))
    return result


def wait_ready(clients):
    for attempt in range(20):
        result = shared_status(clients)
        if result['running'] and result['kernel'] and result['guard_intact'] and not result['userspace']:
            return result
        if attempt < 19:
            time.sleep(.25)
    return verify(clients)


def control(clients, operation):
    if operation not in ('start', 'stop', 'restart'):
        raise ValueError('Unsupported shared VPN operation.')
    state = read_state()
    current = identity(clients, state)
    if operation != 'stop':
        if not guard_intact(clients, state, current):
            raise RuntimeError('The kernel-only startup guard changed. Starting the VPN was refused.')
        clients.run(['modprobe', 'amneziawg'])
        if not Path('/sys/module/amneziawg').is_dir():
            raise RuntimeError('The AmneziaWG kernel module is unavailable.')
    clients.run(['docker', operation, state['container_id']])
    if operation == 'stop':
        result = shared_status(clients)
        if result['running']:
            raise RuntimeError('The shared VPN did not stop.')
        return result
    try:
        return wait_ready(clients)
    except BaseException:
        clients.run(['docker', 'stop', state['container_id']], check=False)
        raise


def protected_digest(path):
    if path.is_symlink():
        raise RuntimeError('Shared VPN removal refuses linked files.')
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
        raise RuntimeError('Shared VPN removal requires protected root-owned regular files.')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned_removal_plan(clients):
    """Read-only reset evidence. Unknown files/identity drift require review."""
    state = read_state()
    current = identity(clients, state)
    if not guard_intact(clients, state, current):
        raise RuntimeError('Shared VPN ownership or startup changed. Automatic removal was refused.')
    paths = {'image/Dockerfile', 'image/start.sh', 'data/awg0.conf', 'data/clientsTable',
             'data/wireguard_server_private_key.key', 'data/wireguard_server_public_key.key',
             'data/wireguard_psk.key'}
    evidence = {}
    for directory in (DIRECTORY, DIRECTORY / 'image', DIRECTORY / 'data'):
        safe_parents(directory)
        for path in directory.iterdir():
            name = path.relative_to(DIRECTORY).as_posix()
            if path.is_symlink() or name not in paths | {'image', 'data'}:
                raise RuntimeError('Unrecognized shared VPN files require manual review before removal.')
    for name in paths:
        evidence[name] = protected_digest(DIRECTORY / name)
    evidence['state'] = protected_digest(STATE)
    # Return hashes and public identities only, never key/config contents.
    result = {'container_id': state['container_id'], 'image_id': state['image_id'],
              'files': evidence, 'source': SOURCE}
    result['digest'] = digest(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return result


def remove_owned(clients, expected):
    """Remove a reviewed owned deployment; caller holds the VPN operation lock.

    This does not uninstall shared Docker/kernel packages or remove other VPN
    installations. Saved guest exports are handled separately by reset's owner.
    """
    plan = owned_removal_plan(clients)
    if plan['digest'] != expected:
        raise RuntimeError('The shared VPN changed after reset review. Refresh the removal preview.')
    clients.run(['docker', 'rm', '-f', plan['container_id']])
    # Recheck each file immediately before deleting it. Another administrator
    # does not honor our lock; preserve changed files and stop on uncertainty.
    for name, fingerprint in plan['files'].items():
        path = STATE if name == 'state' else DIRECTORY / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != fingerprint:
            raise RuntimeError('The shared VPN was removed, but changed private files were preserved. Inspect reset status before retrying.')
        path.unlink()
    for path in (DIRECTORY / 'image', DIRECTORY / 'data', DIRECTORY):
        path.rmdir()
    image = clients.run(['docker', 'image', 'rm', plan['image_id']], check=False)
    result = {'removed': True, 'source': SOURCE}
    if image.returncode:
        result['warning'] = 'The shared VPN was removed; its unused image could not be erased. Other containers were left intact.'
    return result


def check_docker_policy(clients, policy):
    """Docker's normal FORWARD DROP is valid; foreign filtering is not bypassed."""
    policy.check_install_policy(clients.run, ('INPUT',))
    rules = clients.run(['iptables', '-S', 'FORWARD']).stdout.splitlines()
    if not any(v in rules for v in ('-P FORWARD ACCEPT', '-P FORWARD DROP')):
        raise RuntimeError('Unsupported Docker forwarding policy. Review it before setup.')
    allowed = {'ACCEPT', 'LOG', 'NFLOG', 'DOCKER-USER', 'DOCKER-FORWARD'}
    targets = set()
    for line in rules:
        parts = shlex.split(line)
        if parts[:2] != ['-A', 'FORWARD']:
            continue
        target = parts[parts.index('-j') + 1] if '-j' in parts else ''
        if target not in allowed:
            raise RuntimeError('Foreign forwarding restrictions require review before Docker VPN setup.')
        if target.startswith('DOCKER-'):
            if parts != ['-A', 'FORWARD', '-j', target]:
                raise RuntimeError('Conditional Docker forwarding requires manual review.')
            targets.add(target)
    if '-P FORWARD DROP' in rules and not {'DOCKER-USER', 'DOCKER-FORWARD'} <= targets:
        raise RuntimeError('The Docker forwarding hooks could not be verified.')
    users = clients.run(['iptables', '-S', 'DOCKER-USER'], check=False)
    if users.returncode:
        raise RuntimeError('The Docker user-policy chain could not be verified.')
    for line in users.stdout.splitlines():
        parts = shlex.split(line)
        if parts[:2] != ['-A', 'DOCKER-USER']:
            continue
        target = parts[parts.index('-j') + 1] if '-j' in parts else ''
        if target == 'ASHAPP-DKR' and parts == ['-A', 'DOCKER-USER', '-j', target] and policy.managed_firewall():
            continue
        if target not in ('ACCEPT', 'LOG', 'NFLOG', 'RETURN'):
            raise RuntimeError('Existing Docker user-policy restrictions require manual review.')
    check_docker_chains(clients)


def check_docker_chains(clients):
    """Recognize the Docker 28/29 bridge filter shape, not arbitrary chain names.

    Docker inserts port ACCEPT rules in DOCKER before its terminal per-bridge
    DROP. Refuse edits in every reachable chain before that insertion can
    supersede a foreign source restriction. Custom bridge names, routed or
    internal networks require manual review rather than an inferred policy.
    """
    bridge = r'(?:docker0|br-[a-f0-9]{12})'

    def read(chain):
        result = clients.run(['iptables', '-S', chain], check=False)
        if result.returncode:
            raise RuntimeError('The Docker filter chains could not be verified.')
        rules = []
        for line in result.stdout.splitlines():
            words = shlex.split(line)
            if words == ['-N', chain]:
                continue
            if words[:2] != ['-A', chain]:
                raise RuntimeError('Unexpected Docker filter chain metadata.')
            rules.append(' '.join(words[2:]))
        return rules

    forward = read('DOCKER-FORWARD')
    modern = ['-j DOCKER-CT', '-j DOCKER-INTERNAL', '-j DOCKER-BRIDGE']
    legacy = ['-j DOCKER-CT', '-j DOCKER-ISOLATION-STAGE-1', '-j DOCKER-BRIDGE']
    if forward[:3] not in (modern, legacy) or any(
            not re.fullmatch(fr'-i {bridge} -j ACCEPT', rule) for rule in forward[3:]):
        raise RuntimeError('Docker forwarding rules were edited or use an unsupported policy. Review them before setup.')
    for rule in read('DOCKER-CT'):
        if not re.fullmatch(fr'-o {bridge} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', rule):
            raise RuntimeError('Docker connection-tracking rules require manual review.')
    for rule in read('DOCKER-BRIDGE'):
        if not re.fullmatch(fr'-o {bridge} -j DOCKER', rule):
            raise RuntimeError('Docker bridge filtering requires manual review.')
    if forward[:3] == modern:
        if read('DOCKER-INTERNAL'):
            raise RuntimeError('Internal Docker networks require manual firewall review before setup.')
    else:
        for rule in read('DOCKER-ISOLATION-STAGE-1'):
            match = re.fullmatch(fr'-i ({bridge}) ! -o ({bridge}) -j DOCKER-ISOLATION-STAGE-2', rule)
            if rule != '-j RETURN' and (not match or match[1] != match[2]):
                raise RuntimeError('Docker network isolation requires manual review.')
        for rule in read('DOCKER-ISOLATION-STAGE-2'):
            if rule != '-j RETURN' and not re.fullmatch(fr'-o {bridge} -j DROP', rule):
                raise RuntimeError('Docker network isolation requires manual review.')
    for rule in read('DOCKER'):
        drop = re.fullmatch(fr'! -i ({bridge}) -o ({bridge}) -j DROP', rule)
        if drop and drop[1] == drop[2]:
            continue
        accept = re.fullmatch(
            fr'-d ([0-9.]+/32) ! -i ({bridge}) -o ({bridge}) -p (tcp|udp|sctp) -m (tcp|udp|sctp) --dport ([0-9]+) -j ACCEPT', rule)
        if (not accept or accept[2] != accept[3] or accept[4] != accept[5]
                or not 1 <= int(accept[6]) <= 65535):
            raise RuntimeError('Published Docker filtering was edited. Review it before adding a VPN port.')
        ipaddress.IPv4Network(accept[1])


def preflight(clients, setup, policy, host, raw_port, dns):
    port = setup.validate(host, raw_port, dns)
    if clients.run(['uname', '-m']).stdout.strip() not in ('x86_64', 'amd64'):
        raise RuntimeError('Shared AmneziaVPN setup currently supports Linux x86_64 only.')
    if STATE.exists() or STATE.is_symlink() or DIRECTORY.exists() or DIRECTORY.is_symlink():
        raise RuntimeError('Shared deployment storage already exists; it will not be replaced.')
    safe_parents(DIRECTORY.parent)
    safe_parents(STATE.parent)
    if clients.amnezia_containers() or any(clients.AWG_DIR.glob('*.conf')) or (clients.AWG_DIR / 'params').exists():
        raise RuntimeError('An existing VPN deployment will not be replaced. Use its current management mode.')
    for args in (['docker', 'inspect', '--type', 'container', SOURCE], ['docker', 'image', 'inspect', IMAGE]):
        if clients.run(args, check=False).returncode == 0:
            raise RuntimeError('The shared VPN container or image name is occupied. Nothing was replaced.')
    if clients.run(['pgrep', '-x', 'amneziawg-go'], check=False).returncode == 0:
        raise RuntimeError('A userspace AmneziaWG process is already running.')
    check_docker_policy(clients, policy)
    for route in json.loads(clients.run(['ip', '-j', '-4', 'route', 'show']).stdout):
        dest = route.get('dst', 'default')
        if dest != 'default' and ipaddress.ip_network(dest, strict=False).overlaps(SUBNET):
            raise RuntimeError('The VPN subnet overlaps an existing host route.')
    # Refuse overlapping private Docker networks before a tunnel route is added.
    networks = clients.run(['docker', 'network', 'ls', '--quiet']).stdout.split()
    print('[INFO] Shared kernel: checking Docker networks for address conflicts.', flush=True)
    if networks:
        for network in json.loads(clients.run(['docker', 'network', 'inspect', *networks]).stdout):
            for value in network.get('IPAM', {}).get('Config') or []:
                if value.get('Subnet') and ipaddress.ip_network(value['Subnet']).version == 4 and ipaddress.ip_network(value['Subnet']).overlaps(SUBNET):
                    raise RuntimeError('The VPN subnet overlaps an existing Docker network.')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(('0.0.0.0', port))
    return port


def install(clients, base=None):
    base = base or Path(__file__).resolve().parent
    setup, policy = load_module('awg_setup'), load_module('firewall_policy')
    fields = clients.read_fields()
    if len(fields) != 3:
        raise ValueError('Expected an IPv4 address, UDP port and DNS address.')
    host, raw_port, dns = fields
    print('[INFO] Shared kernel: checking installation prerequisites.', flush=True)
    port = preflight(clients, setup, policy, host, raw_port, dns)
    print('[INFO] Shared kernel: installing the reviewed kernel packages.', flush=True)
    setup.install_kernel_packages(clients, base)
    private = clients.run(['awg', 'genkey']).stdout.strip()
    public = clients.run(['awg', 'pubkey'], private + '\n').stdout.strip()
    psk = clients.run(['awg', 'genpsk']).stdout.strip()
    if not all(re.fullmatch(r'[A-Za-z0-9+/]{43}=', value) for value in (private, public, psk)):
        raise RuntimeError('The VPN tools returned invalid server keys.')
    config = configure_shared(setup, host, port, dns, private, public)
    contents = {'image/Dockerfile': DOCKERFILE, 'image/start.sh': STARTUP,
                'data/awg0.conf': config, 'data/clientsTable': '[]\n',
                'data/wireguard_server_private_key.key': private + '\n',
                'data/wireguard_server_public_key.key': public + '\n',
                'data/wireguard_psk.key': psk + '\n'}
    created_container = created_image = None
    directory_created = False
    state_content = None
    nonce = secrets.token_hex(16)
    try:
        DIRECTORY.mkdir(mode=0o700)
        directory_created = True
        for directory in ('image', 'data'):
            (DIRECTORY / directory).mkdir(mode=0o700)
        for name, value in contents.items():
            clients.atomic_write(DIRECTORY / name, value, 0o700 if name.endswith('start.sh') else 0o600)
        print('[INFO] Shared kernel: building the digest-pinned container image.', flush=True)
        clients.run(['docker', 'build', '--pull', '--label', 'io.ashapp.setup-id=' + nonce,
                     '--tag', IMAGE, str(DIRECTORY / 'image')])
        images = json.loads(clients.run(['docker', 'image', 'inspect', IMAGE]).stdout)
        if (len(images) != 1 or not re.fullmatch(r'sha256:[a-f0-9]{64}', images[0]['Id'])
                or images[0].get('Config', {}).get('Labels', {}).get('io.ashapp.setup-id') != nonce
                or images[0].get('Config', {}).get('Labels', {}).get('io.ashapp.managed') != OWNER):
            raise RuntimeError('The new VPN image identity could not be verified.')
        created_image = images[0]['Id']
        print('[INFO] Shared kernel: creating the protected container.', flush=True)
        created_container = clients.run([
            'docker', 'create', '--name', SOURCE, '--restart', 'unless-stopped',
            '--label', 'io.ashapp.managed=' + OWNER, '--label', 'io.ashapp.setup-id=' + nonce,
            '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--cap-add', 'DAC_OVERRIDE',
            '--security-opt', 'no-new-privileges:true', '--log-driver', 'none',
            '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv4.conf.all.src_valid_mark=1',
            '--mount', f'type=bind,source={DIRECTORY / "data"},target={CONTAINER_DATA}',
            '--network', 'bridge', '--publish', f'0.0.0.0:{port}:{port}/udp', created_image]).stdout.strip()
        if not re.fullmatch(r'[a-f0-9]{64}', created_container):
            raise RuntimeError('The new VPN container identity could not be verified.')
        STATE.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        state_content = json.dumps(dict(
            schema=1, source=SOURCE, container_id=created_container, image_id=created_image,
            port=port, endpoint=host, dns=dns, protocol_version='2', base_image=BASE_IMAGE, startup_sha256=digest(STARTUP))) + '\n'
        clients.atomic_write(STATE, state_content)
        print('[INFO] Shared kernel: starting and verifying the kernel interface.', flush=True)
        clients.run(['docker', 'start', created_container])
        result = wait_ready(clients)
        return dict(installed=True, source=SOURCE, awg_port=port, kernel=result['kernel'])
    except BaseException:
        recover = False
        # No name-based force deletion: match this attempt's nonce and IDs first.
        current = clients.run(['docker', 'inspect', '--type', 'container', SOURCE], check=False)
        if current.returncode == 0:
            values = json.loads(current.stdout)
            if len(values) == 1 and values[0].get('Config', {}).get('Labels', {}).get('io.ashapp.setup-id') == nonce:
                created_container = values[0]['Id']
                recover |= clients.run(['docker', 'rm', '-f', created_container], check=False).returncode != 0
            else:
                recover = True
        if not created_image:
            image = clients.run(['docker', 'image', 'inspect', IMAGE], check=False)
            if image.returncode == 0:
                values = json.loads(image.stdout)
                if len(values) == 1 and values[0].get('Config', {}).get('Labels', {}).get('io.ashapp.setup-id') == nonce:
                    created_image = values[0]['Id']
                else:
                    recover = True
        if created_image:
            recover |= clients.run(['docker', 'image', 'rm', created_image], check=False).returncode != 0
        if not recover and directory_created:
            try:
                safe_parents(DIRECTORY / 'image')
                safe_parents(DIRECTORY / 'data')
            except (RuntimeError, OSError):
                recover = True
        if not recover and directory_created:
            for name, value in contents.items():
                path = DIRECTORY / name
                if path.exists():
                    if path.is_symlink() or path.read_text() != value:
                        recover = True
                    else:
                        path.unlink()
            if not recover:
                if STATE.exists() or STATE.is_symlink():
                    if STATE.is_symlink() or state_content is None or STATE.read_text() != state_content:
                        recover = True
                    else:
                        STATE.unlink()
                for path in (DIRECTORY / 'image', DIRECTORY / 'data', DIRECTORY):
                    if path.exists():
                        try:
                            path.rmdir()
                        except OSError:
                            recover = True
        if recover:
            raise RuntimeError('Shared setup failed and private recovery files were retained. Review the owned container/storage before retrying.') from None
        raise


def main(arguments=()):
    if os.geteuid() != 0:
        raise ValueError('Shared kernel setup requires root.')
    os.umask(0o077)
    clients = load_module('clients')
    if list(arguments) == ['--verify']:
        clients.emit(verify(clients))
        return
    if arguments:
        raise ValueError('Unknown shared VPN setup operation.')
    # Share the peer-management lock to serialize installation against client edits.
    import fcntl
    lock = Path('/run/ashapp/clients.lock')
    safe_parents(lock.parent)
    lock.parent.mkdir(mode=0o700, exist_ok=True)
    if lock.is_symlink():
        raise RuntimeError('Unsafe VPN operation lock.')
    with lock.open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        clients.emit(install(clients))


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except RuntimeError as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Do not echo private configuration, registry responses or command output.
        print('ERROR: shared kernel setup failed. Check the deployment prerequisites and activity step.', file=sys.stderr)
        sys.exit(1)

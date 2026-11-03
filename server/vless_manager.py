#!/usr/bin/env python3
"""Isolated, root-managed VLESS/REALITY/Vision service using sing-box."""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import stat
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import tarfile

VERSION = '1.14.4'
RELEASES = {
    'x86_64': ('sing-box-1.14.4-linux-amd64.tar.gz', '699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968'),
    'aarch64': ('sing-box-1.14.4-linux-arm64.tar.gz', '436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26'),
}
SOURCE = 'vless-reality'
FLOW = 'xtls-rprx-vision'
SERVICE = 'ashapp-vless.service'
USER = 'ashapp-vless'
BINARY = Path('/usr/local/lib/ashapp/sing-box')
DIRECTORY = Path('/etc/ashapp/vless')
UNIT = Path('/etc/systemd/system') / SERVICE
FIREWALL = Path('/usr/share/netfilter-persistent/plugins.d/91-ashapp-vless')
HOSTNAME = re.compile(r'(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\Z')


def hostname(value):
    if not isinstance(value, str) or not HOSTNAME.fullmatch(value):
        raise ValueError('Enter a DNS hostname for Reality SNI, without a scheme, path or port.')
    return value.lower()


def endpoint(value):
    if not isinstance(value, str):
        raise ValueError('Invalid server address.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return hostname(value)


def port_number(value):
    if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    return int(value)


def client_name(value):
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 64 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Use a client name of 1–64 characters without control characters.')
    return value


def key_valid(value):
    try:
        return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{43}', value)) and len(base64.urlsafe_b64decode(value + '=')) == 32
    except ValueError:
        return False


def checked_state(state):
    if not isinstance(state, dict) or state.get('schema') != 1 or state.get('owner') != 'Ashapp':
        raise ValueError('Unsupported Ashapp VLESS state. Existing files were not changed.')
    endpoint(state.get('address'))
    hostname(state.get('sni'))
    port_number(state.get('port'))
    if state.get('fingerprint') not in ('chrome', 'firefox', 'safari', 'edge') or not key_valid(state.get('private_key')) or not key_valid(state.get('public_key')):
        raise ValueError('Invalid Reality settings.')
    clients = state.get('clients')
    if not isinstance(clients, list) or len(clients) > 1000:
        raise ValueError('Invalid VLESS client list.')
    identities, names, short_ids = set(), set(), set()
    for client in clients:
        if not isinstance(client, dict):
            raise ValueError('Invalid VLESS client record.')
        name = client_name(client.get('name'))
        identity = client.get('uuid')
        try:
            identity_valid = isinstance(identity, str) and str(uuid.UUID(identity)) == identity
        except ValueError:
            identity_valid = False
        if not identity_valid or not isinstance(client.get('short_id'), str) or not re.fullmatch(r'[0-9a-f]{16}', client['short_id']):
            raise ValueError('Invalid VLESS identity.')
        if identity in identities or name in names or client['short_id'] in short_ids:
            raise ValueError('Duplicate VLESS identity or name.')
        identities.add(identity); names.add(name); short_ids.add(client['short_id'])
    return state


def server_config(state):
    checked_state(state)
    return {
        'log': {'level': 'error'},
        'inbounds': [{
            'tag': 'ashapp-vless', 'listen': '0.0.0.0', 'listen_port': state['port'], 'type': 'vless',
            'users': [{'uuid': c['uuid'], 'flow': FLOW} for c in state['clients']],
            'tls': {'enabled': True, 'server_name': state['sni'], 'reality': {
                'enabled': True, 'handshake': {'server': state['sni'], 'server_port': 443},
                'private_key': state['private_key'],
                'short_id': [c['short_id'] for c in state['clients']] or ['0000000000000000'],
            }},
        }],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
    }


def encoded(value):
    return json.dumps(value, indent=2, ensure_ascii=True) + '\n'


def run(args, data=None, check=True):
    try:
        result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        if check:
            raise RuntimeError('VLESS system command unavailable or timed out.') from None
        return subprocess.CompletedProcess(args, 127, '', '')
    if check and result.returncode:
        # Output can include private configuration; never echo it.
        raise RuntimeError('VLESS command failed; previous configuration is preserved where possible.')
    return result


def write(path, content, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('Unsafe VLESS file path.')
    fd, temporary = tempfile.mkstemp(prefix='.ashapp-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def probe_target(sni):
    try:
        addresses = socket.getaddrinfo(sni, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError('Reality SNI could not be resolved from this server. Check the hostname and DNS.') from None
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('Reality SNI must resolve to public addresses.')
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    # Try checked addresses, preserving SNI/certificate verification and allowing
    # IPv4 fallback when the VPS has no working IPv6 route.
    for address in list(dict.fromkeys(item[4][0] for item in addresses))[:4]:
        try:
            with socket.create_connection((address, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=sni) as tls:
                    if tls.selected_alpn_protocol() == 'h2':
                        return
        except OSError:
            continue
    raise ValueError('Reality target could not be verified with TLS 1.3 and HTTP/2 from this server. Choose another SNI or check its network.')


def existing_public_directory(path):
    if path.is_symlink() or (path.exists() and
            (not path.is_dir() or not path.stat().st_mode & stat.S_IXOTH)):
        raise RuntimeError('The VLESS service cannot traverse an existing private or linked parent directory. Review its ownership and permissions before retrying; existing permissions were not widened.')


def public_directory(path):
    """Make newly created non-secret service ancestors traversable under umask077."""
    existing_public_directory(path)
    missing = []
    current = path
    while not current.exists():
        if current.is_symlink():
            raise RuntimeError('Unsafe VLESS directory.')
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise RuntimeError('Unsafe VLESS directory.')
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)


def install_binary():
    machine = platform.machine()
    if machine not in RELEASES:
        raise ValueError('VLESS installation supports Linux x86_64 and aarch64 only.')
    archive, digest = RELEASES[machine]
    url = f'https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{archive}'
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('VLESS download checksum failed. Nothing was installed.')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as bundle:
        entry = bundle.getmember(archive.removesuffix('.tar.gz') + '/sing-box')
        if not entry.isfile() or entry.size > 100 * 1024 * 1024:
            raise RuntimeError('Invalid VLESS binary size.')
        binary = bundle.extractfile(entry).read()
    if not binary.startswith(b'\x7fELF'):
        raise RuntimeError('Invalid VLESS binary.')
    public_directory(BINARY.parent)
    if BINARY.parent.is_symlink() or BINARY.exists() or BINARY.is_symlink():
        raise RuntimeError('The dedicated VLESS binary path is already occupied.')
    fd = os.open(BINARY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o755)
            output.write(binary)
    except Exception:
        BINARY.unlink(missing_ok=True)
        raise


def firewall_text(port):
    port = port_number(port)
    rule = f'INPUT -p tcp --dport {port} -m comment --comment ashapp-vless -j ACCEPT'
    return f'''#!/bin/sh
set -eu
case "${{1:-}}" in
 start|restart|reload)
  iptables -C {rule} 2>/dev/null || iptables -I {rule}
  ;;
 flush)
  if iptables -C {rule} 2>/dev/null; then iptables -D {rule}; fi
  ;;
 *) : ;;
esac
'''


def unit_text():
    return f'''[Unit]
Description=Ashapp VLESS Reality (sing-box {VERSION})
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User={USER}
Group={USER}
ExecStart={BINARY} run -c {DIRECTORY / 'config.json'}
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''


class VlessManager:
    def __init__(self, directory=DIRECTORY, command=run, writer=write, unit=UNIT):
        self.directory, self.command, self.writer, self.unit = Path(directory), command, writer, Path(unit)
        self.state_path = self.directory / 'state.json'
        self.config_path = self.directory / 'config.json'
        self.pending_path = self.directory / 'pending-transaction'
        self.warning = None

    def running(self):
        return self.command(['systemctl', 'is-active', '--quiet', SERVICE], check=False).returncode == 0

    def load(self):
        if self.pending_path.exists() or self.pending_path.is_symlink():
            raise RuntimeError('An VLESS transaction was interrupted. Inspect the protected recovery files and service before retrying.')
        if self.directory.is_symlink() or self.state_path.is_symlink() or self.config_path.is_symlink():
            raise RuntimeError('Unsafe VLESS configuration path.')
        state = checked_state(json.loads(self.state_path.read_text(encoding='utf-8')))
        current = json.loads(self.config_path.read_text(encoding='utf-8'))
        expected = server_config(state)
        if expected != current:
            raise RuntimeError('VLESS configuration changed outside Ashapp. Refusing to overwrite it.')
        return state

    def status(self):
        configured = self.directory.exists() or self.directory.is_symlink() or self.unit.exists() or self.unit.is_symlink()
        result = {'vless_configured': configured, 'vless': False}
        if configured:
            try:
                state = self.load()
                result.update(vless=self.running(), vless_port=state['port'], vless_sni=state['sni'], vless_version=VERSION, vless_engine='sing-box')
            except (OSError, ValueError, RuntimeError, KeyError, TypeError):
                result['vless_error'] = 'Ashapp VLESS configuration could not be verified. Existing files were not changed.'
        return result

    def rows(self):
        if not self.state_path.exists():
            return []
        return [{'name': c['name'], 'source': SOURCE, 'protocol': 'vless', 'public_key': c['uuid'],
                 'configured': True, 'stats_available': False, 'can_export': True, 'can_import': False,
                 'can_revoke': True, 'can_rename': True} for c in self.load()['clients']]

    def apply(self, state, initial=False):
        self.warning = None
        checked_state(state)
        before = None if initial else self.load()
        previous_state = None if initial else self.state_path.read_text(encoding='utf-8')
        previous_config = None if initial else self.config_path.read_text(encoding='utf-8')
        active = self.running()
        candidate = self.directory / 'candidate.json'
        config = encoded(server_config(state))
        changed = False
        try:
            self.writer(candidate, config, 0o600)
            self.command([str(BINARY), 'check', '-c', str(candidate)])
            if not initial and self.load() != before:
                raise RuntimeError('VLESS state changed concurrently. Refresh first.')
            # Durable recovery copies contain secrets and are root-only.
            if previous_state is not None:
                self.writer(self.directory / 'recovery-state.json', previous_state)
                self.writer(self.directory / 'recovery-config.json', previous_config)
            self.writer(self.pending_path, 'VLESS apply in progress; confirm saved and active configuration before removing this marker.\n')
            changed = True
            self.writer(self.config_path, config, 0o640)
            self.command(['chown', 'root:' + USER, str(self.config_path)])
            self.writer(self.state_path, encoded(state))
            if active or initial:
                self.command(['systemctl', 'restart', SERVICE])
                self.verify_running()
        except Exception:
            if previous_state is not None and changed:
                try:
                    self.writer(self.config_path, previous_config, 0o640)
                    self.command(['chown', 'root:' + USER, str(self.config_path)])
                    self.writer(self.state_path, previous_state)
                    if active:
                        self.command(['systemctl', 'restart', SERVICE]); self.verify_running()
                    self.pending_path.unlink()
                except Exception:
                    raise RuntimeError('VLESS update and recovery failed. Root-only recovery files remain; inspect the service before retrying.') from None
            raise
        else:
            for path in (self.pending_path, self.directory / 'recovery-state.json', self.directory / 'recovery-config.json'):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    self.warning = 'VLESS access changes applied. Protected transaction files need manual cleanup before further changes.'
        finally:
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                self.warning = 'VLESS configuration processing finished. A protected temporary file needs manual cleanup.'

    def verify_running(self):
        consecutive = 0
        for _ in range(10):
            consecutive = consecutive + 1 if self.running() else 0
            if consecutive >= 3:
                return
            time.sleep(0.3)
        raise RuntimeError('The dedicated VLESS service did not start.')

    def install(self, address, port, sni, fingerprint):
        address, port, sni = endpoint(address), port_number(port), hostname(sni)
        if fingerprint not in ('chrome', 'firefox', 'safari', 'edge'):
            raise ValueError('Unsupported Reality fingerprint.')
        if self.state_path.exists():
            self.load()
            return {'preserved': True, **self.status()}
        if self.directory.exists() or self.directory.is_symlink() or self.unit.exists() or self.unit.is_symlink() or BINARY.exists() or BINARY.is_symlink() or FIREWALL.exists() or FIREWALL.is_symlink():
            raise RuntimeError('Dedicated VLESS paths are occupied. Existing installations will not be replaced.')
        existing_public_directory(self.directory.parent)
        existing_public_directory(BINARY.parent)
        try:
            with socket.socket() as probe:
                probe.bind(('0.0.0.0', port))
        except OSError:
            raise ValueError('The selected VLESS TCP port is unavailable. Choose another port.') from None
        probe_target(sni)
        account = self.command(['getent', 'passwd', USER], check=False)
        if account.returncode == 0:
            fields = account.stdout.strip().split(':')
            if len(fields) != 7 or not fields[2].isdigit() or not 0 < int(fields[2]) < 1000 or fields[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
                raise RuntimeError('The dedicated VLESS account is occupied by a regular login account.')
            group = self.command(['getent', 'group', USER]).stdout.strip().split(':')
            if len(group) != 4 or group[2] != fields[3] or set(filter(None, group[3].split(','))) - {USER}:
                raise RuntimeError('The dedicated VLESS group is not private to its service account.')
        created_binary = directory_created = unit_created = firewall_created = False
        try:
            install_binary()
            created_binary = True
            if account.returncode != 0:
                self.command(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', USER])
            public_directory(self.directory.parent)
            self.directory.mkdir(mode=0o750)
            directory_created = True
            self.command(['chown', 'root:' + USER, str(self.directory)])
            self.directory.chmod(0o750)
            generated = self.command([str(BINARY), 'generate', 'reality-keypair']).stdout
            values = dict(re.findall(r'(?m)^(PrivateKey|Password|PublicKey|Private key|Public key):\s*(\S+)\s*$', generated))
            private = values.get('PrivateKey') or values.get('Private key')
            public = values.get('Password') or values.get('PublicKey') or values.get('Public key')
            state = dict(schema=1, owner='Ashapp', address=address, port=port, sni=sni,
                         fingerprint=fingerprint, private_key=private, public_key=public, clients=[])
            checked_state(state)
            self.writer(self.unit, unit_text(), 0o644)
            unit_created = True
            self.command(['systemctl', 'daemon-reload'])
            self.apply(state, initial=True)
            FIREWALL.parent.mkdir(parents=True, exist_ok=True)
            self.writer(FIREWALL, firewall_text(port), 0o755)
            firewall_created = True
            self.command([str(FIREWALL), 'start'])
            self.command(['systemctl', 'enable', 'netfilter-persistent'])
            self.command(['systemctl', 'enable', SERVICE])
        except Exception:
            try:
                if unit_created:
                    self.command(['systemctl', 'disable', '--now', SERVICE])
                    if self.running():
                        raise RuntimeError('Service still running.')
                if firewall_created:
                    self.command([str(FIREWALL), 'flush']); FIREWALL.unlink()
                if directory_created:
                    for name in ('state.json', 'config.json', 'pending-transaction', 'candidate.json'):
                        (self.directory / name).unlink(missing_ok=True)
                    self.directory.rmdir()
                if unit_created:
                    self.unit.unlink(); self.command(['systemctl', 'daemon-reload'])
                if created_binary:
                    BINARY.unlink()
            except Exception:
                raise RuntimeError('VLESS installation stopped and cleanup needs attention. Dedicated protected files remain; inspect the service before retrying.') from None
            raise RuntimeError('VLESS installation failed. New service files were removed; existing VPN services were not changed. Refresh before retrying.') from None
        return {'installed': True, **self.status()}

    def identity(self, state, identity):
        clients = [c for c in state['clients'] if c['uuid'] == identity]
        if len(clients) != 1:
            raise ValueError('The VLESS client no longer exists. Refresh first.')
        return clients[0]

    def action(self, action, fields):
        if action == 'add-client' and len(fields) == 2:
            state = self.load()
            name = client_name(fields[0])
            if any(c['name'] == name for c in state['clients']):
                raise ValueError('A VLESS client with this name already exists.')
            state['clients'].append(dict(name=name, uuid=str(uuid.uuid4()), short_id=secrets.token_hex(8)))
            self.apply(state)
            return {'created': True, **({'warning': self.warning} if self.warning else {})}
        if action not in ('get-client', 'revoke-client', 'rename-client') or len(fields) != (4 if action == 'rename-client' else 3):
            raise ValueError('Invalid VLESS client operation.')
        state = self.load()
        client = self.identity(state, fields[2])
        if action == 'get-client':
            # Explicit allowlist. Server private key and administration never leave the manager.
            return {'connection': {'name': client['name'], 'uuid': client['uuid'], 'address': state['address'],
                    'port': state['port'], 'sni': state['sni'], 'public_key': state['public_key'],
                    'short_id': client['short_id'], 'fingerprint': state['fingerprint'], 'flow': FLOW}}
        if action == 'revoke-client':
            state['clients'].remove(client)
        else:
            replacement = client_name(fields[3])
            if any(c is not client and c['name'] == replacement for c in state['clients']):
                raise ValueError('A VLESS client with this name already exists.')
            client['name'] = replacement
        self.apply(state)
        return {'revoked' if action == 'revoke-client' else 'renamed': True,
                **({'warning': self.warning} if self.warning else {})}

    def control(self, operation):
        if operation not in ('start', 'stop', 'restart'):
            raise ValueError('Invalid VLESS service operation.')
        self.load()
        if operation != 'stop':
            self.command([str(BINARY), 'check', '-c', str(self.config_path)])
        self.command(['systemctl', operation, SERVICE])
        if operation != 'stop':
            self.verify_running()
        return {'ok': True}


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Root is required.')
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError('VLESS request is too large.')
    fields = raw.rstrip(b'\0').decode('utf-8').split('\0')
    manager = VlessManager()
    if sys.argv[1] == 'install-vless' and len(fields) == 4:
        result = manager.install(*fields)
    elif sys.argv[1] == 'vless-control' and len(fields) == 1:
        result = manager.control(fields[0])
    else:
        raise ValueError('Invalid VLESS operation.')
    print('ASHAPP_JSON:' + json.dumps(result), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print('ERROR: ' + str(exc) if isinstance(exc, (ValueError, RuntimeError)) else 'ERROR: VLESS operation failed; inspect the dedicated service.', file=sys.stderr)
        sys.exit(1)

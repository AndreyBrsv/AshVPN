"""Manage peers of existing official AmneziaVPN containers; never install a VPN."""
import base64
import copy
import hashlib
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timezone

CONTAINERS = {'amnezia-awg': ('wg0', 'wg'), 'amnezia-awg2': ('awg0', 'awg')}
EXTENSIONS = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
              'I1', 'I2', 'I3', 'I4', 'I5', 'HeaderProtectionKey', 'ContentPaddingAddition',
              'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
              'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies'}
MAX_CONFIG_BYTES = 128 * 1024
SHARED_PARAMETERS = {'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'HeaderProtectionKey'}

# All program text is fixed. Configs, keys and names arrive only over stdin.
# A killed transaction leaves the private lock/backups in place and fails closed.
TRANSACTION = r'''
set -euo pipefail
umask 077
cd /opt/amnezia/awg
iface="$1"; tool="$2"; operation="$3"
cfg="$iface.conf"; table=clientsTable
[[ ! -L .ashapp-client-lock ]] && mkdir .ashapp-client-lock || exit 70
work="$(mktemp -d .ashapp-transaction.XXXXXXXX)"
changed=0; live_changed=0; committed=0
hash() { sha256sum "$1" | cut -d ' ' -f1; }
cleanup() {
  local original_status="$1"
  local failed=0
  trap - EXIT
  set +e
  if [[ "$committed" != 1 && "$changed" == 1 ]]; then
    if [[ "$(hash "$cfg")" == "$new_cfg_hash" ]]; then
      cp "$work/old.conf" "$cfg" || failed=1
    else failed=1; fi
    if [[ -f "$table" && "$(hash "$table")" == "$new_table_hash" ]]; then
      if [[ "$expected_table" == MISSING ]]; then rm -f "$table" || failed=1
      else cp "$work/old.table" "$table" || failed=1; fi
    elif [[ "$table_written" == 1 ]]; then failed=1; fi
    if [[ "$live_changed" == 1 ]]; then
      if [[ "$operation" == add ]]; then "$tool" set "$iface" peer "$key" remove >/dev/null 2>&1 || failed=1
      elif [[ "$operation" == revoke ]]; then "$tool" addconf "$iface" "$work/old.peer" >/dev/null 2>&1 || failed=1; fi
      "$tool" show "$iface" peers > "$work/rollback.keys" 2>/dev/null || failed=1
      if [[ "$operation" == add ]]; then
        if grep -qxF -- "$key" "$work/rollback.keys"; then failed=1; fi
      elif [[ "$operation" == revoke ]]; then
        grep -qxF -- "$key" "$work/rollback.keys" || failed=1
      fi
    fi
  fi
  if [[ "$failed" == 1 ]]; then
    printf 'ASHAPP_TX_RECOVERY_REQUIRED\n'
  else
    if [[ "$committed" != 1 ]]; then printf 'ASHAPP_TX_ROLLED_BACK\n'; fi
    rm -rf -- "$work"
    rmdir .ashapp-client-lock
  fi
  exit "$original_status"
}
trap 'cleanup "$?"' EXIT
trap 'exit 71' HUP INT TERM
read -r expected_cfg; read -r expected_table; read -r key
for file in new.conf new.table new.peer old.peer; do read -r value; printf '%s' "$value" | base64 -d > "$work/$file"; done
[[ -f "$cfg" && ! -L "$cfg" && ! -L "$table" ]] || exit 72
[[ "$(hash "$cfg")" == "$expected_cfg" ]] || exit 73
if [[ "$expected_table" == MISSING ]]; then [[ ! -e "$table" ]] || exit 73
else [[ -f "$table" && "$(hash "$table")" == "$expected_table" ]] || exit 73; cp "$table" "$work/old.table"; fi
cp "$cfg" "$work/old.conf"
new_cfg_hash="$(hash "$work/new.conf")"; new_table_hash="$(hash "$work/new.table")"
table_written=0; changed=1
mv "$work/new.conf" "$cfg"
mv "$work/new.table" "$table"; table_written=1
if [[ "$operation" == add ]]; then
  live_changed=1; "$tool" addconf "$iface" "$work/new.peer" >/dev/null 2>&1
elif [[ "$operation" == revoke ]]; then
  live_changed=1; "$tool" set "$iface" peer "$key" remove >/dev/null 2>&1
fi
if [[ "$operation" != rename ]]; then
  "$tool" show "$iface" peers > "$work/live.keys"
  if [[ "$operation" == add ]]; then grep -qxF -- "$key" "$work/live.keys" || exit 75
  elif grep -qxF -- "$key" "$work/live.keys"; then exit 75
  else [[ "$?" == 1 ]] || exit 75; fi
fi
[[ "$(hash "$cfg")" == "$new_cfg_hash" && "$(hash "$table")" == "$new_table_hash" ]] || exit 73
committed=1
printf 'ASHAPP_TX_OK\n'
'''


def key_valid(value):
    try:
        return isinstance(value, str) and len(value) == 44 and len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


def validate_name(name):
    if not name or name != name.strip() or len(name) > 64 or any(
            unicodedata.category(c).startswith('C') for c in name):
        raise RuntimeError('Use a client name of 1–64 characters without control characters.')


class TransactionError(RuntimeError):
    def __init__(self, message, rollback_confirmed=False):
        super().__init__(message)
        self.rollback_confirmed = rollback_confirmed


def sections(text):
    matches = list(re.finditer(r'(?m)^[ \t]*\[Peer\][ \t\r]*$', text))
    return [(m.start(), matches[i + 1].start() if i + 1 < len(matches) else len(text))
            for i, m in enumerate(matches)]


def parse_configuration(content):
    """Accept a portable client config, never executable wg-quick hooks."""
    if not isinstance(content, str) or len(content.encode('utf-8')) > MAX_CONFIG_BYTES or '\0' in content:
        raise RuntimeError('Choose a client .conf file no larger than 128 KiB.')
    parsed = {}
    current = None
    allowed = {'Interface': {'PrivateKey', 'Address', 'DNS', 'MTU'} | EXTENSIONS,
               'Peer': {'PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'}}
    for raw in content.lstrip('\ufeff').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            if current not in allowed or current in parsed:
                raise RuntimeError('Use a client configuration with one Interface and one Peer.')
            parsed[current] = {}
            continue
        if current is None or '=' not in line:
            raise RuntimeError('The client configuration format is unsupported.')
        name, value = [part.strip() for part in line.split('=', 1)]
        if name not in allowed[current] or name in parsed[current] or not value:
            raise RuntimeError('The client configuration contains unsupported or duplicate settings.')
        parsed[current][name] = value
    if set(parsed) != {'Interface', 'Peer'}:
        raise RuntimeError('Use a client configuration with one Interface and one Peer.')
    return parsed['Interface'], parsed['Peer']


def validate_configuration(content, cfg, peer_cfg, public, derive_public, expected_port=None):
    interface, peer = parse_configuration(content)
    if not all(key_valid(k) for k in (public, interface.get('PrivateKey'), peer.get('PublicKey'))):
        raise RuntimeError('The configuration does not contain valid client/server keys.')
    if peer.get('PresharedKey') and not key_valid(peer['PresharedKey']):
        raise RuntimeError('The configuration does not contain a valid preshared key.')
    if derive_public(interface['PrivateKey']) != public or derive_public(cfg['PrivateKey']) != peer['PublicKey']:
        raise RuntimeError('The private configuration no longer matches this server and client.')
    if peer.get('PresharedKey', '') != peer_cfg.get('PresharedKey', ''):
        raise RuntimeError('The private configuration no longer matches the client preshared key.')
    try:
        addresses = [ipaddress.ip_interface(s.strip()).ip for s in interface['Address'].split(',')]
        routes = [ipaddress.ip_network(s.strip(), strict=False) for s in peer_cfg['AllowedIPs'].split(',')]
        for route in peer['AllowedIPs'].split(','):
            ipaddress.ip_network(route.strip(), strict=False)
        if not addresses or any(not any(ip in route for route in routes) for ip in addresses):
            raise ValueError()
    except (KeyError, ValueError):
        raise RuntimeError('The saved client addresses no longer match the VPN peer. Import an up-to-date configuration.') from None
    for name in SHARED_PARAMETERS:
        if name in cfg and interface.get(name, '0' if name.startswith('S') else '') != cfg[name]:
            raise RuntimeError('The saved obfuscation settings no longer match this VPN. Import an up-to-date configuration.')
    endpoint = re.fullmatch(r'(?:\[[0-9a-fA-F:.%]+\]|[A-Za-z0-9_.-]+):([0-9]{1,5})', peer.get('Endpoint', ''))
    if not endpoint or not 1 <= int(endpoint[1]) <= 65535:
        raise RuntimeError('The client endpoint is missing or invalid.')
    if expected_port is not None and int(endpoint[1]) != expected_port:
        raise RuntimeError('The saved endpoint port no longer matches this VPN. Import an up-to-date configuration.')


class ContainerClients:
    def __init__(self, source, run, write, assignments, peers, directory):
        if source not in CONTAINERS:
            raise RuntimeError('Unsupported VPN source.')
        self.source, self.run, self.write, self.fields, self.peers = source, run, write, assignments, peers
        self.iface, self.tool = CONTAINERS[source]
        self.prefix = ['docker', 'exec', '-i', source]
        self.config_path = '/opt/amnezia/awg/' + self.iface + '.conf'
        self.directory = directory / source

    def read(self, path, optional=False):
        # Preserve original CRLF bytes: text=True normalizes raw `cat` output.
        result = self.run(self.prefix + ['base64', path], check=False)
        if result.returncode == 0:
            try:
                return base64.b64decode(''.join(result.stdout.split()), validate=True).decode('utf-8')
            except (ValueError, UnicodeError):
                raise RuntimeError('The container configuration could not be decoded.') from None
        if optional and self.run(self.prefix + ['test', '-e', path], check=False).returncode == 1:
            return None
        raise RuntimeError('The container configuration could not be read. Refresh before retrying.')

    def configuration(self):
        text = self.read(self.config_path)
        cfg = self.fields(text.split('[Peer]', 1)[0])
        if not key_valid(cfg.get('PrivateKey')):
            raise RuntimeError('Unsupported VPN server key.')
        return text, cfg

    def snapshot(self):
        text, cfg = self.configuration()
        if cfg.get('SaveConfig', '').lower() == 'true':
            raise RuntimeError('Unsupported VPN configuration; no clients were changed.')
        raw = self.read('/opt/amnezia/awg/clientsTable', optional=True)
        try:
            table = json.loads(raw) if raw is not None else []
            if isinstance(table, list):
                if any(not isinstance(e, dict) or not isinstance(e.get('userData', {}), dict)
                       or not isinstance(e.get('clientId'), str) for e in table):
                    raise ValueError()
                ids = [e['clientId'] for e in table]
            elif isinstance(table, dict) and all(isinstance(e, dict) for e in table.values()):
                ids = list(table)
            else:
                raise ValueError()
            if len(ids) != len(set(ids)):
                raise ValueError()
            if any(not isinstance(data.get('clientName', ''), str) for _, data in self.records(table)):
                raise ValueError()
        except (ValueError, TypeError):
            raise RuntimeError('The client table is malformed or ambiguous; no clients were changed.') from None
        runtime = self.run(self.prefix + [self.tool, 'showconf', self.iface]).stdout
        return text, cfg, raw, table, runtime

    def records(self, table):
        return table.items() if isinstance(table, dict) else (
            (e['clientId'], e.get('userData', {})) for e in table)

    def update_table(self, table, key, name=None):
        updated = copy.deepcopy(table)
        if isinstance(updated, dict):
            if name is None:
                updated.pop(key, None)
            else:
                updated.setdefault(key, {})['clientName'] = name
        else:
            entries = [e for e in updated if e['clientId'] == key]
            if name is None:
                updated = [e for e in updated if e['clientId'] != key]
            else:
                if not entries:
                    entries = [{'clientId': key, 'userData': {
                        'creationDate': datetime.now(timezone.utc).isoformat()}}]
                    updated.extend(entries)
                entries[0].setdefault('userData', {})['clientName'] = name
        return json.dumps(updated, ensure_ascii=True, indent=2) + '\n'

    def export_path(self, key):
        if not key_valid(key):
            raise RuntimeError('Invalid client public key.')
        return self.directory / (hashlib.sha256(key.encode()).hexdigest() + '.conf')

    def transact(self, old, raw_table, new, table, operation, key, new_peer='', old_peer=''):
        digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
        lines = [digest(old), digest(raw_table) if raw_table is not None else 'MISSING', key]
        lines.extend(base64.b64encode(s.encode()).decode() for s in (new, table, new_peer, old_peer))
        result = self.run(self.prefix + ['bash', '-c', TRANSACTION, '--', self.iface, self.tool, operation],
                          '\n'.join(lines) + '\n', check=False)
        if 'ASHAPP_TX_RECOVERY_REQUIRED' in result.stdout:
            raise TransactionError('Client update failed and needs recovery. Private backups and the lock remain in /opt/amnezia/awg. Do not retry until the server configuration is checked.')
        if result.returncode or 'ASHAPP_TX_OK' not in result.stdout:
            raise TransactionError('Client update did not complete. Refresh before retrying; a concurrent edit or interrupted transaction may need attention.',
                                   rollback_confirmed='ASHAPP_TX_ROLLED_BACK' in result.stdout)

    def find_peer(self, text, key):
        if not key_valid(key):
            raise RuntimeError('Invalid client public key.')
        found = [(start, end) for start, end in sections(text)
                 if self.fields(text[start:end]).get('PublicKey') == key]
        if len(found) != 1:
            raise RuntimeError('The client is missing or ambiguous. Refresh the client list.')
        return found[0]

    def rename(self, key, name):
        validate_name(name)
        text, cfg, raw, table, runtime = self.snapshot()
        self.find_peer(text, key)
        if any(k != key and e.get('clientName', '').casefold() == name.casefold() for k, e in self.records(table)):
            raise RuntimeError('A client with this name already exists in this VPN.')
        self.transact(text, raw, text, self.update_table(table, key, name), 'rename', key)
        return {'renamed': True}

    def revoke(self, key):
        text, cfg, raw, table, runtime = self.snapshot()
        start, end = self.find_peer(text, key)
        live = [(a, b) for a, b in sections(runtime) if self.fields(runtime[a:b]).get('PublicKey') == key]
        if len(live) != 1:
            raise RuntimeError('The live peer could not be verified. Refresh before revoking access.')
        self.transact(text, raw, text[:start] + text[end:], self.update_table(table, key),
                      'revoke', key, old_peer=runtime[live[0][0]:live[0][1]])
        result = {'revoked': True}
        try:
            self.export_path(key).unlink(missing_ok=True)
        except OSError:
            result['warning'] = 'Access was revoked, but the old private export could not be erased. Remove it from protected server storage.'
        return result

    def public_port(self, cfg):
        port = int(cfg['ListenPort'])
        mapped = self.run(['docker', 'port', self.source, f'{port}/udp'], check=False)
        ports = {int(line.rsplit(':', 1)[1]) for line in mapped.stdout.splitlines() if ':' in line}
        if not ports:
            mode = self.run(['docker', 'inspect', '--type', 'container', '--format', '{{.HostConfig.NetworkMode}}', self.source]).stdout.strip()
            if mode != 'host':
                raise RuntimeError('The public UDP port could not be determined.')
            ports = {port}
        if len(ports) != 1 or not 1 <= next(iter(ports)) <= 65535:
            raise RuntimeError('The public UDP port is ambiguous or invalid.')
        return next(iter(ports))

    def add(self, name, endpoint, dns):
        validate_name(name)
        host = str(ipaddress.ip_address(endpoint))
        dns = str(ipaddress.ip_address(dns))
        text, cfg, raw, table, runtime = self.snapshot()
        if any(e.get('clientName', '').casefold() == name.casefold() for _, e in self.records(table)):
            raise RuntimeError('A client with this name already exists in this VPN.')
        servers = [ipaddress.ip_interface(s.strip()) for s in cfg['Address'].split(',')]
        reserved = [ipaddress.ip_network(a.strip(), strict=False)
                    for p in self.peers(text) + self.peers(runtime)
                    for a in p.get('AllowedIPs', '').split(',') if a.strip()]
        chosen = []
        for server in servers:
            used = {s.ip for s in servers}
            # Official AmneziaVPN allocates from the final saved peer address.
            # Appending a reused lower hole makes its next client collide with
            # a higher existing peer. Keep new addresses monotonic in the
            # shared configuration while also reserving runtime-only routes.
            last = max([int(server.ip)] + [int(route.broadcast_address) for route in reserved
                        if route.version == server.version and route.overlaps(server.network)])
            first = max(1, last - int(server.network.network_address) + 1)
            for offset in range(first, min(server.network.num_addresses - 1, 65535)):
                ip = server.network.network_address + offset
                if ip not in used and not any(ip in route for route in reserved):
                    chosen.append(str(ip) + ('/32' if ip.version == 4 else '/128'))
                    reserved.append(ipaddress.ip_network(chosen[-1]))
                    break
            else:
                raise RuntimeError('No addresses remain after the existing peers. Reusing earlier addresses is unsafe with AmneziaVPN management.')
        private = self.run(self.prefix + [self.tool, 'genkey']).stdout.strip()
        public = self.run(self.prefix + [self.tool, 'pubkey'], private + '\n').stdout.strip()
        server_public = self.run(self.prefix + [self.tool, 'pubkey'], cfg['PrivateKey'] + '\n').stdout.strip()
        psk = self.run(self.prefix + [self.tool, 'genpsk']).stdout.strip()
        if not all(key_valid(k) for k in (private, public, server_public, psk)):
            raise RuntimeError('The VPN tool did not generate valid keys.')
        if any(p.get('PublicKey') == public for p in self.peers(text) + self.peers(runtime)):
            raise RuntimeError('A generated key already exists; no clients were changed.')
        port = self.public_port(cfg)
        host = '[' + host + ']' if ':' in host else host
        client = ['[Interface]', 'PrivateKey = ' + private, 'Address = ' + ', '.join(chosen), 'DNS = ' + dns]
        client.extend(k + ' = ' + v for k, v in cfg.items() if k in EXTENSIONS)
        client += ['', '[Peer]', 'PublicKey = ' + server_public, 'PresharedKey = ' + psk,
                   f'Endpoint = {host}:{port}', 'AllowedIPs = 0.0.0.0/0, ::/0',
                   'PersistentKeepalive = 25', '']
        peer = '[Peer]\nPublicKey = ' + public + '\nPresharedKey = ' + psk + '\nAllowedIPs = ' + ', '.join(chosen) + '\n'
        destination = self.export_path(public)
        if destination.exists():
            raise RuntimeError('A private export already exists; it will not be replaced.')
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.write(destination, '\n'.join(client))
        try:
            self.transact(text, raw, text.rstrip() + '\n\n' + peer,
                          self.update_table(table, public, name), 'add', public, new_peer=peer)
        except TransactionError as error:
            if error.rollback_confirmed:
                destination.unlink(missing_ok=True)
            # Keep the private file for recovery if the outcome is uncertain.
            raise
        return {'created': True, 'public_key': public}

    def export(self, key):
        text, cfg = self.configuration()
        start, end = self.find_peer(text, key)
        destination = self.export_path(key)
        if not destination.is_file() or destination.is_symlink():
            raise RuntimeError('The original private configuration is unavailable. Existing private keys cannot be recovered from public keys.')
        content = destination.read_bytes().decode('utf-8')
        self.validate_export(content, cfg, self.fields(text[start:end]), key)
        return {'config': content}

    def validate_export(self, content, cfg, peer_cfg, key):
        validate_configuration(content, cfg, peer_cfg, key,
                               lambda private: self.run(self.prefix + [self.tool, 'pubkey'], private + '\n').stdout.strip(),
                               expected_port=self.public_port(cfg))

    def import_configuration(self, key, content, replace=False):
        text, cfg = self.configuration()
        start, end = self.find_peer(text, key)
        self.validate_export(content, cfg, self.fields(text[start:end]), key)
        destination = self.export_path(key)
        if destination.is_symlink() or (destination.exists() and not replace):
            raise RuntimeError('A saved private configuration already exists; it will not be replaced.')
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.write(destination, content)
        return {'imported': True}

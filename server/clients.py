#!/usr/bin/env python3
"""Root-only AWG management and JSON reporting. No shell interpolation or secret logs."""
from __future__ import annotations

import fcntl
import ipaddress
import importlib.util
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

AWG_DIR = Path("/etc/amnezia/amneziawg")
CLIENTS_DIR = Path("/var/lib/ashapp/clients")
SOCKS_NAME = "amnezia-socks5proxy"
SOCKS_CONFIG = "/usr/local/3proxy/conf/3proxy.cfg"
SHARED_AWG_STATE = Path('/var/lib/ashapp/amnezia-awg2/deployment.json')
CLIENT_RE = re.compile(r"[A-Za-z0-9_-]{1,15}\Z", re.ASCII)
IFACE_RE = re.compile(r"[A-Za-z0-9_]{1,15}\Z", re.ASCII)
AMNEZIA_AWG = {
    'amnezia-awg': ('wg0', 'wg'),
    'amnezia-awg2': ('awg0', 'awg'),
}


def run(args, data=None, check=True):
    try:
        proc = subprocess.run(args, input=data, text=True, capture_output=True)
    except FileNotFoundError:
        if check:
            raise RuntimeError('Missing server command: ' + args[0]) from None
        return subprocess.CompletedProcess(args, 127, '', '')
    if check and proc.returncode:
        # Commands may involve configs/keys. Never dump stdout/stderr into errors.
        raise RuntimeError("Command failed: " + args[0])
    return proc


def emit(value):
    print("ASHAPP_JSON:" + json.dumps(value, ensure_ascii=True), flush=True)


def read_fields():
    raw = sys.stdin.buffer.read().split(b"\0")
    if raw and raw[-1] == b"":
        raw.pop()
    return [item.decode("utf-8") for item in raw]


def atomic_write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".ashapp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def assignments(text):
    result = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def interface_values(text):
    part = text.split("[Peer]", 1)[0]
    return assignments(part)


def settings():
    params = assignments((AWG_DIR / "params").read_text())
    iface = params.get("SERVER_AWG_NIC", "awg0")
    if not IFACE_RE.fullmatch(iface):
        raise RuntimeError("Invalid AWG interface name.")
    path = AWG_DIR / (iface + ".conf")
    text = path.read_text()
    if interface_values(text).get("SaveConfig", "false").lower() == "true":
        raise RuntimeError("SaveConfig=true prevents safe client management.")
    return params, iface, path, text


def peer_blocks(text):
    """Keep Varckin's marker format, so its original management menu still works."""
    matches = list(re.finditer(r"(?m)^### Client ([A-Za-z0-9_-]{1,15})[ \t]*$", text))
    records = []
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        peers = list(re.finditer(r"(?m)^\[Peer\][ \t]*$", text[match.end():end]))
        if len(peers) > 1:
            end = match.end() + peers[1].start()
        records.append((match.group(1), match.start(), end, assignments(text[match.end():end])))
    return records


def runtime_peers(iface):
    peers = {}
    for block in run(['awg', 'showconf', iface]).stdout.split('[Peer]')[1:]:
        cfg = assignments(block)
        public = cfg.get('PublicKey')
        if not public or public in peers:
            raise RuntimeError('Active VPN peers could not be verified. Refresh first.')
        peers[public] = cfg
    return peers


def peer_matches(actual, expected):
    if actual is None or expected is None:
        return actual is expected
    def routes(peer):
        return {ipaddress.ip_network(s.strip(), strict=False) for s in peer.get('AllowedIPs', '').split(',') if s.strip()}
    return (actual.get('PublicKey') == expected.get('PublicKey')
            and actual.get('PresharedKey', '') == expected.get('PresharedKey', '')
            and routes(actual) == routes(expected))


def apply_peer(iface, public, peer):
    if peer is None:
        run(['awg', 'set', iface, 'peer', public, 'remove'])
    else:
        # addconf merges only this peer; syncconf would remove runtime-only peers.
        text = '[Peer]\n' + ''.join(f'{key} = {value}\n' for key, value in peer.items())
        run(['awg', 'addconf', iface, '/dev/stdin'], text)
    if not peer_matches(runtime_peers(iface).get(public), peer):
        raise RuntimeError('The selected active VPN peer could not be verified.')


class PeerRecoveryError(RuntimeError):
    pass


def change_host_peer(iface, path, original, new, public, before, after, live):
    if path.read_text() != original or runtime_peers(iface) != live:
        raise RuntimeError('VPN configuration changed concurrently. Refresh first.')
    try:
        atomic_write(path, new)
        apply_peer(iface, public, after)
    except Exception:
        try:
            if path.read_text() not in (new, original):
                raise RuntimeError('Saved VPN configuration changed during recovery.')
            atomic_write(path, original)
            apply_peer(iface, public, before)
        except Exception:
            raise PeerRecoveryError('VPN peer update and recovery could not be verified. Inspect the saved configuration and active interface before retrying. Any new private export was retained in protected server storage.') from None
        raise


def verified_kernel(iface):
    if not Path("/sys/module/amneziawg").exists():
        return False
    proc = run(["ip", "-d", "link", "show", "dev", iface], check=False)
    return proc.returncode == 0 and "amneziawg" in proc.stdout


def amnezia_containers():
    """Discover existing official deployments without starting or modifying them."""
    proc = run(['docker', 'container', 'ls', '-a', '--format', '{{.Names}}'], check=False)
    if proc.returncode == 127:
        return []
    if proc.returncode:
        raise RuntimeError('Docker VPN discovery failed. Check Docker in the hosting console, then refresh.')
    found = []
    for name in proc.stdout.splitlines():
        if name not in AMNEZIA_AWG:
            continue
        state = run(['docker', 'inspect', '--type', 'container', '--format', '{{json .State}}', name], check=False)
        try:
            value = json.loads(state.stdout) if state.returncode == 0 else None
            if not isinstance(value, dict) or not isinstance(value.get('Running'), bool):
                raise ValueError()
        except (ValueError, TypeError):
            raise RuntimeError('An AmneziaVPN container could not be inspected. Refresh before making changes.') from None
        iface, tool = AMNEZIA_AWG[name]
        found.append({'source': name, 'running': value['Running'],
                      'interface': iface, 'tool': tool, 'protocol': 'amneziawg',
                      'manager': 'AmneziaVPN', 'owned': False})
    return found


def external_awg_details(container):
    """Describe the protocol and data plane without adopting an external service."""
    result = dict(container, protocol='amneziawg', manager='AmneziaVPN', owned=False,
                  kernel=False, userspace=False, data_plane='unknown')
    if not container['running']:
        return result
    source, iface = container['source'], container['interface']
    try:
        config = run(['docker', 'exec', source, 'cat', '/opt/amnezia/awg/' + iface + '.conf'], check=False)
        if config.returncode:
            raise ValueError()
        cfg = interface_values(config.stdout)
        result['port'] = container_manager(source).public_port(cfg)
        if any(cfg.get(key) for key in ('HeaderProtectionKey', 'ContentPaddingAddition',
                                      'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime',
                                      'KeepaliveTimeout', 'MaxHandshakeAttempts')) or any(
                cfg.get(key, '').strip() and cfg[key].strip().lower() != 'off'
                for key in ('RandomTrailers', 'DisableCookies')):
            result['protocol_version'] = '3.1'
        elif any(cfg.get(key) for key in ('S3', 'S4')) or any('-' in cfg.get(key, '') for key in ('H1', 'H2', 'H3', 'H4')):
            result['protocol_version'] = '2'
        elif any(cfg.get(key) for key in ('I1', 'I2', 'I3', 'I4', 'I5')):
            result['protocol_version'] = '1.5'
        else:
            result['protocol_version'] = 'legacy'
        link = run(['docker', 'exec', source, 'ip', '-d', '-j', 'link', 'show', 'dev', iface], check=False)
        processes = run(['docker', 'top', source, '-eo', 'pid,comm'], check=False)
        rows = [line.split(None, 1) for line in processes.stdout.splitlines()]
        commands = [parts[1].strip() for parts in rows if len(parts) == 2 and parts[0].isdecimal()]
        if link.returncode or processes.returncode or not commands:
            raise ValueError()
        links = json.loads(link.stdout)
        result['userspace'] = 'amneziawg-go' in commands
        result['kernel'] = (isinstance(links, list)
                            and any(isinstance(value, dict) and isinstance(value.get('linkinfo'), dict)
                                    and value['linkinfo'].get('info_kind') == 'amneziawg'
                                    and 'UP' in value.get('flags', []) for value in links)
                            and not result['userspace'])
        result['data_plane'] = 'userspace' if result['userspace'] else 'kernel' if result['kernel'] else 'unknown'
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError):
        result['error'] = 'The external AmneziaWG configuration or active data plane could not be verified.'
    return result


def configured_peers(text):
    """Read every peer, including peers without an Ashapp/Varckin marker."""
    sections = re.split(r'(?m)^[ \t]*\[Peer\][ \t\r]*$', text)[1:]
    return [assignments(section) for section in sections if assignments(section).get('PublicKey')]


def client_names(text):
    """Current Amnezia clientsTable array and its older public-key map format."""
    value = json.loads(text)
    if isinstance(value, dict):
        value = [{'clientId': key, 'userData': data} for key, data in value.items()]
    if not isinstance(value, list):
        raise ValueError('Unsupported client table.')
    names = {}
    for entry in value:
        if not isinstance(entry, dict) or not isinstance(entry.get('clientId'), str):
            continue
        data = entry.get('userData')
        name = data.get('clientName') if isinstance(data, dict) else None
        if isinstance(name, str) and name.strip():
            names[entry['clientId']] = name.strip()[:200]
    return names


def client_helpers():
    spec = importlib.util.spec_from_file_location('ashapp_amnezia', Path(__file__).with_name('amnezia_clients.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def container_manager(source):
    return client_helpers().ContainerClients(source, run, atomic_write, assignments, configured_peers,
                                   CLIENTS_DIR / 'amnezia')


def vless_manager():
    spec = importlib.util.spec_from_file_location('ashapp_vless', Path(__file__).with_name('vless_manager.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VlessManager()


def shared_awg_manager():
    spec = importlib.util.spec_from_file_location('ashapp_shared_awg', Path(__file__).with_name('amnezia_setup.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shared_awg_backend():
    # Use the current command/file functions, including injected fixture ones.
    return SimpleNamespace(**globals())


def shared_awg_status():
    if not SHARED_AWG_STATE.exists() and not SHARED_AWG_STATE.is_symlink():
        return {'configured': False}
    try:
        return shared_awg_manager().shared_status(shared_awg_backend())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return {'configured': True, 'running': False, 'kernel': False,
                'guard_intact': False, 'error': 'The shared VPN deployment could not be verified. Inspect it before changing services.'}


def live_peers(command):
    # dump contains private and preshared keys. Only public fields leave this function.
    proc = run(command, check=False)
    if proc.returncode:
        return {}, False
    lines = proc.stdout.splitlines()
    if not lines or len(lines[0].split('\t')) < 4:
        return {}, False
    peers = {}
    try:
        for line in lines[1:]:
            fields = line.split('\t')
            if len(fields) >= 8:
                peers[fields[0]] = {'addresses': fields[3], 'handshake': int(fields[4]),
                                    'rx': int(fields[5]), 'tx': int(fields[6])}
    except ValueError:
        return {}, False
    return peers, True


def peer_rows(text, live, names, source, stats_available, managed=None, revoke_allowed=False):
    managed = managed or {}
    configured = {cfg['PublicKey']: cfg.get('AllowedIPs', '') for cfg in configured_peers(text)}
    keys = dict.fromkeys([*configured, *live, *names])
    rows = []
    for key in keys:
        name = names.get(key) or managed.get(key) or 'Peer ' + key[:12]
        owned = key in managed
        exportable = False
        if owned:
            try:
                client_path(source, managed[key])
                exportable = True
            except RuntimeError:
                pass
        rows.append({'name': name, 'public_key': key, 'source': source,
                     'addresses': configured.get(key, ''), 'handshake': 0, 'rx': 0, 'tx': 0,
                     **live.get(key, {}), 'stats_available': stats_available,
                     'configured': key in configured or key in live,
                     'can_export': exportable,
                     'can_import': owned,
                     'can_rename': owned,
                     'can_revoke': owned and stats_available and revoke_allowed})
    return rows


def status():
    result = {"awg": False, "kernel": False, "userspace": False, "socks5": False}
    result['architecture'] = platform.machine()
    try:
        result.update(vless_manager().status())
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        result.update(vless=False, vless_error='The VLESS service status could not be read.')
    result["awg_configured"] = (AWG_DIR / "params").exists() or any(AWG_DIR.glob("*.conf"))
    result['awg_host_configured'] = result['awg_configured']
    result["userspace"] = run(["pgrep", "-x", "amneziawg-go"], check=False).returncode == 0
    if (AWG_DIR / "params").exists():
        try:
            params, iface, path, text = settings()
            cfg = interface_values(text)
            result.update({"interface": iface, "awg_port": int(cfg["ListenPort"]),
                           "kernel": verified_kernel(iface),
                           "awg": run(["systemctl", "is-active", "--quiet", "awg-quick@" + iface], check=False).returncode == 0,
                           "clients": len(peer_blocks(text))})
        except (OSError, ValueError, KeyError, RuntimeError):
            result['awg_error'] = 'Existing VPN configuration could not be read. Repair it before changing clients.'
    try:
        result['external_awg'] = [external_awg_details(container) for container in amnezia_containers()]
        if result['external_awg']:
            result['awg_configured'] = True
    except RuntimeError as error:
        result['vpn_detection_error'] = str(error)
    shared = shared_awg_status()
    if shared.get('configured'):
        result.update({'awg_deployment': 'amnezia', 'awg_configured': True,
                       'awg_shared_guard': shared.get('guard_intact') is True,
                       'awg_owned': shared.get('guard_intact') is True and not shared.get('error'),
                       'awg_source': 'amnezia-awg2'})
        if result['awg_host_configured']:
            result['awg_error'] = 'Conflicting host and shared VPN deployments require manual review.'
            result['kernel'] = False
        else:
            result['awg'] = shared.get('running') is True
            result['kernel'] = (shared.get('kernel') is True and shared.get('guard_intact') is True
                                and not shared.get('userspace') and not shared.get('error'))
            result['userspace'] = result['userspace'] or shared.get('userspace') is True
            if isinstance(shared.get('port'), int):
                result['awg_port'] = shared['port']
            if shared.get('error'):
                result['awg_error'] = shared['error']
    if run(["sh", "-c", "command -v docker >/dev/null"], check=False).returncode == 0:
        for name, field, target in ((SOCKS_NAME, "socks5", None),):
            proc = run(["docker", "inspect", "--type", "container", name], check=False)
            if proc.returncode == 0:
                result[field + '_configured'] = True
                try:
                    values = json.loads(proc.stdout)
                    if not isinstance(values, list) or len(values) != 1:
                        raise ValueError()
                    obj = values[0]
                    if not isinstance(obj['State']['Running'], bool):
                        raise ValueError()
                    identity = obj.get('Id', '')
                    if not isinstance(identity, str) or not re.fullmatch(r'[a-f0-9]{64}', identity):
                        raise ValueError()
                    result[field] = obj['State']['Running']
                    result['socks5_source'] = SOCKS_NAME
                    result['socks5_container_id'] = identity
                    labels = (obj.get('Config') or {}).get('Labels') or {}
                    result['socks5_owned'] = labels.get('io.ashapp.managed') == 'socks5-v1'
                    bindings = [binding for key, entries in socks_publications(obj).items()
                                if key.endswith('/tcp') for binding in entries or []]
                    ports = {int(binding['HostPort']) for binding in bindings}
                    if len(ports) != 1 or not 1 <= next(iter(ports)) <= 65535:
                        raise ValueError()
                    result[field + '_port'] = next(iter(ports))
                    result[field + '_access'] = 'private' if all(
                        ipaddress.ip_address(binding.get('HostIp') or '0.0.0.0').is_loopback
                        for binding in bindings) else 'public'
                    if result[field + '_access'] == 'private':
                        try:
                            require_private_socks_engine()
                            result['socks5_private_supported'] = True
                        except RuntimeError as error:
                            result['socks5_private_supported'] = False
                            result['socks5_access_warning'] = str(error)
                except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
                    result['socks5_error'] = 'The SOCKS5 container or published port could not be inspected. Other server services are still shown.'
    icmp = run(["iptables", "-C", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"], check=False)
    owned_icmp = run(["iptables", "-C", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-m", "comment", "--comment", "ashapp-owned-icmp-v1", "-j", "DROP"], check=False)
    result["icmp_blocked"] = icmp.returncode == 0 or owned_icmp.returncode == 0
    proc = run(["/usr/sbin/sshd", "-T"], check=False)
    result["ssh"] = dict(line.split(None, 1) for line in proc.stdout.splitlines()
                         if line.startswith(("permitrootlogin ", "passwordauthentication ")))
    if proc.returncode or len(result['ssh']) != 2:
        result['ssh_error'] = 'The SSH daemon policy could not be inspected. Validate sshd configuration and its runtime service before changing access.'
    result["reboot_required"] = Path("/var/run/reboot-required").exists()
    return result


def list_clients():
    rows, warnings = [], []
    try:
        rows.extend(vless_manager().rows())
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        warnings.append('VLESS: the saved clients could not be verified. Other VPN clients are still shown.')
    managed_path = None
    try:
        _, _, managed_path, _ = settings()
    except (OSError, ValueError, KeyError, RuntimeError):
        pass  # A missing params file must not hide an otherwise readable config.
    for path in sorted(AWG_DIR.glob('*.conf')):
        iface = path.stem
        if not IFACE_RE.fullmatch(iface):
            continue
        try:
            text = path.read_text()
        except OSError:
            warnings.append('Host ' + iface + ': VPN configuration could not be read.')
            continue
        live, available = live_peers(['awg', 'show', iface, 'dump'])
        managed = {}
        blocks = peer_blocks(text)
        names = {cfg['PublicKey']: name for name, _, _, cfg in blocks if cfg.get('PublicKey')}
        if path == managed_path:
            # Duplicate names or keys are not safe mutation targets.
            for name, _, _, cfg in blocks:
                key = cfg.get('PublicKey')
                if key and sum(b[0] == name or b[3].get('PublicKey') == key for b in blocks) == 1:
                    managed[key] = name
        rows.extend(peer_rows(text, live, names, iface, available, managed,
                              revoke_allowed=verified_kernel(iface)))
        if not available:
            warnings.append('Host ' + iface + ': live statistics unavailable; saved clients are still shown.')
    try:
        containers = amnezia_containers()
    except RuntimeError as error:
        containers = []
        warnings.append(str(error))
    for container in containers:
        source, iface = container['source'], container['interface']
        if not container['running']:
            warnings.append(source + ': container is stopped. Start it in AmneziaVPN to read its clients.')
            continue
        prefix = ['docker', 'exec', source]
        config = run(prefix + ['cat', '/opt/amnezia/awg/' + iface + '.conf'], check=False)
        table = run(prefix + ['cat', '/opt/amnezia/awg/clientsTable'], check=False)
        names = {}
        if table.returncode == 0:
            try:
                names = client_names(table.stdout)
            except ValueError:
                warnings.append(source + ': client names could not be read; peers are identified by public key.')
        else:
            warnings.append(source + ': client names unavailable; peers are identified by public key.')
        if config.returncode:
            warnings.append(source + ': saved VPN configuration could not be read.')
        live, available = live_peers(prefix + [container['tool'], 'show', iface, 'dump'])
        external_rows = peer_rows(config.stdout if config.returncode == 0 else '', live, names,
                                  source, available)
        manager = container_manager(source)
        for row in external_rows:
            row['name_key'] = row['name'].casefold()
            row['can_revoke'] = config.returncode == 0 and available and row['configured']
            row['can_rename'] = config.returncode == 0 and row['configured']
            row['can_import'] = config.returncode == 0 and row['configured']
            try:
                saved = manager.export_path(row['public_key'])
                row['can_export'] = saved.is_file() and not saved.is_symlink()
            except RuntimeError:
                row['can_export'] = False
                row['can_revoke'] = False
                row['can_rename'] = False
                row['can_import'] = False
        rows.extend(external_rows)
        if not available:
            warnings.append(source + ': live statistics unavailable; saved clients are still shown.')
    return {'clients': rows, 'warnings': warnings}


def client_path(iface, name):
    if not CLIENT_RE.fullmatch(name):
        raise RuntimeError("Invalid client name.")
    filename = f"{iface}-client-{name}.conf"
    candidates = [CLIENTS_DIR / filename, Path("/root") / filename]
    candidates.extend(Path("/home").glob("*/" + filename))
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise RuntimeError("Client file is missing. A private key cannot be recovered from a public key.")


def add_client(name):
    if not CLIENT_RE.fullmatch(name):
        raise RuntimeError("Invalid client name.")
    params, iface, path, original = settings()
    if any(item[0] == name for item in peer_blocks(original)):
        raise RuntimeError("A client with this name already exists.")
    if not verified_kernel(iface):
        raise RuntimeError("A running kernel interface is required to add clients.")
    cfg = interface_values(original)
    live = runtime_peers(iface)
    server_addresses = [ipaddress.ip_interface(s.strip()) for s in cfg["Address"].split(",")]
    # Reserve complete routed networks, including peers without a Varckin marker.
    # A peer with /24 AllowedIPs owns that route, not just its first address.
    reserved = []
    for peer in original.split("[Peer]")[1:]:
        for address in assignments(peer).get("AllowedIPs", "").split(","):
            if address.strip():
                reserved.append(ipaddress.ip_network(address.strip(), strict=False))
    for peer in live.values():
        for address in peer.get('AllowedIPs', '').split(','):
            if address.strip():
                reserved.append(ipaddress.ip_network(address.strip(), strict=False))
    server_ips = {item.ip for item in server_addresses}
    chosen = []
    for server in server_addresses:
        candidate = None
        for offset in range(2, min(server.network.num_addresses - 1, 65535)):
            ip = server.network.network_address + offset
            if ip not in server_ips and not any(ip in route for route in reserved):
                candidate = str(ip) + ("/32" if ip.version == 4 else "/128")
                reserved.append(ipaddress.ip_network(candidate))
                break
        if candidate is None:
            raise RuntimeError("No addresses remain in the VPN subnet.")
        chosen.append(candidate)
    private = run(["awg", "genkey"]).stdout.strip()
    public = run(["awg", "pubkey"], private + "\n").stdout.strip()
    if public in live:
        raise RuntimeError('Generated client identity already exists. Retry with a new key.')
    server_public = run(["awg", "pubkey"], cfg["PrivateKey"] + "\n").stdout.strip()
    psk = run(["awg", "genpsk"]).stdout.strip()
    dns = params.get("CLIENT_DNS_1", "1.1.1.1")
    secondary = params.get("CLIENT_DNS_2", "")
    if secondary and secondary != dns:
        dns += ", " + secondary
    client = ["[Interface]", "PrivateKey = " + private, "Address = " + ", ".join(chosen), "DNS = " + dns]
    for key, value in cfg.items():
        if key in {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
                   "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "RandomTrailers", "DisableCookies"}:
            client.append(key + " = " + value)
    endpoint = params["SERVER_PUB_IP"]
    if ":" in endpoint and not (endpoint.startswith("[") and endpoint.endswith("]")):
        endpoint = "[" + endpoint + "]"
    client.extend(["", "[Peer]", "PublicKey = " + server_public, "PresharedKey = " + psk,
                   "Endpoint = " + endpoint + ":" + cfg["ListenPort"],
                   "AllowedIPs = " + params.get("ALLOWED_IPS", "0.0.0.0/0"), "PersistentKeepalive = 25", ""])
    new = original.rstrip() + f"\n\n### Client {name}\n[Peer]\nPublicKey = {public}\nPresharedKey = {psk}\nAllowedIPs = {','.join(chosen)}\n"
    destination = CLIENTS_DIR / f"{iface}-client-{name}.conf"
    if destination.exists():
        raise RuntimeError("The client file already exists; automatic replacement is forbidden.")
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    CLIENTS_DIR.chmod(0o700)
    atomic_write(destination, "\n".join(client))
    try:
        change_host_peer(iface, path, original, new, public, None,
                         dict(PublicKey=public, PresharedKey=psk, AllowedIPs=','.join(chosen)), live)
    except PeerRecoveryError:
        raise
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return {"name": name, "created": True}


def get_client(name):
    params, iface, path, text = settings()
    blocks = [cfg for item, _, _, cfg in peer_blocks(text) if item == name]
    if len(blocks) != 1:
        raise RuntimeError("Client not found.")
    content = client_path(iface, name).read_bytes().decode('utf-8')
    client_helpers().validate_configuration(content, interface_values(text), blocks[0], blocks[0].get('PublicKey'),
        lambda private: run(['awg', 'pubkey'], private + '\n').stdout.strip(),
        expected_port=int(interface_values(text)['ListenPort']))
    return {"name": name, "config": content}


def import_client_configuration(name, public, content, replace=False):
    _, iface, _, text = settings()
    blocks = [cfg for item, _, _, cfg in peer_blocks(text) if item == name]
    if len(blocks) != 1 or blocks[0].get('PublicKey') != public:
        raise RuntimeError('The client identity changed. Refresh first.')
    client_helpers().validate_configuration(content, interface_values(text), blocks[0], public,
        lambda private: run(['awg', 'pubkey'], private + '\n').stdout.strip(),
        expected_port=int(interface_values(text)['ListenPort']))
    destination = CLIENTS_DIR / f'{iface}-client-{name}.conf'
    try:
        previous = client_path(iface, name)
    except RuntimeError:
        previous = None
    if destination.is_symlink() or (previous is not None and not replace):
        raise RuntimeError('A private configuration already exists; select Replace saved copy to update it.')
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    CLIENTS_DIR.chmod(0o700)
    atomic_write(destination, content)
    return {'imported': True}


def revoke_client(name):
    if not CLIENT_RE.fullmatch(name):
        raise RuntimeError("Invalid client name.")
    params, iface, path, original = settings()
    matches = [(start, end) for item, start, end, _ in peer_blocks(original) if item == name]
    if len(matches) != 1:
        raise RuntimeError("Client name is missing or ambiguous.")
    start, end = matches[0]
    new = original[:start] + original[end:]
    public = assignments(original[start:end])['PublicKey']
    live = runtime_peers(iface)
    before = live.get(public)
    change_host_peer(iface, path, original, new, public, before, None, live)
    try:
        client_path(iface, name).unlink()
    except RuntimeError:
        pass
    except OSError:
        return {'revoked': True, 'warning': 'Access was revoked, but the old private export could not be erased. Remove it from protected server storage.'}
    return {"revoked": True}


def client_action(action, fields):
    """UI mutations use an explicit source/public key; setup keeps its host-only API."""
    name = fields[0]
    source = fields[1] if len(fields) > 1 else ''
    if source == 'vless-reality':
        return vless_manager().action(action, fields)
    if source in AMNEZIA_AWG:
        if action == 'add-client' and source == 'amnezia-awg2':
            shared = shared_awg_status()
            if shared.get('configured') and (not all(shared.get(key) is True
                    for key in ('running', 'kernel', 'guard_intact'))
                    or shared.get('userspace') or shared.get('error')):
                raise RuntimeError('The shared kernel VPN must pass its safety checks before creating clients.')
        manager = container_manager(source)
        if action == 'add-client' and len(fields) == 4:
            return manager.add(name, fields[2], fields[3])
        if action == 'rename-client' and len(fields) == 4:
            return manager.rename(fields[2], fields[3])
        if action == 'get-client' and len(fields) == 3:
            return manager.export(fields[2])
        if action == 'revoke-client' and len(fields) == 3:
            return manager.revoke(fields[2])
        if action == 'import-client' and len(fields) == 5 and fields[4] in ('yes', 'no'):
            return manager.import_configuration(fields[2], fields[3], replace=fields[4] == 'yes')
        raise RuntimeError('Invalid container client operation.')
    if source:
        _, iface, _, text = settings()
        if source != iface:
            raise RuntimeError('The selected VPN source changed. Refresh first.')
        if action != 'add-client':
            blocks = [cfg for item, _, _, cfg in peer_blocks(text) if item == name]
            expected = {'rename-client': 4, 'import-client': 5}.get(action, 3)
            if len(fields) != expected or len(blocks) != 1 or blocks[0].get('PublicKey') != fields[2]:
                raise RuntimeError('The client identity changed. Refresh first.')
    elif len(fields) != 1:
        raise RuntimeError('Invalid host client operation.')
    if action == 'add-client':
        return add_client(name)
    if action == 'get-client':
        return get_client(name)
    if action == 'revoke-client':
        return revoke_client(name)
    if action == 'rename-client':
        return rename_client(name, fields[3])
    if action == 'import-client' and source and fields[4] in ('yes', 'no'):
        return import_client_configuration(name, fields[2], fields[3], replace=fields[4] == 'yes')
    raise RuntimeError('This VPN source does not support renaming clients.')


def rename_client(name, replacement):
    if not CLIENT_RE.fullmatch(replacement):
        raise RuntimeError('Use up to 15 letters, numbers, underscores or hyphens.')
    _, iface, path, original = settings()
    if any(n == replacement for n, _, _, _ in peer_blocks(original)):
        raise RuntimeError('A client with this name already exists.')
    matches = [(start, end) for n, start, end, _ in peer_blocks(original) if n == name]
    if len(matches) != 1:
        raise RuntimeError('The client is missing or ambiguous.')
    start, end = matches[0]
    block = original[start:end].replace('### Client ' + name, '### Client ' + replacement, 1)
    previous = None
    try:
        previous = client_path(iface, name)
    except RuntimeError:
        pass
    destination = CLIENTS_DIR / f'{iface}-client-{replacement}.conf'
    if destination.exists():
        raise RuntimeError('The destination client file already exists.')
    candidate = original[:start] + block + original[end:]
    replacing = False
    try:
        if previous:
            atomic_write(destination, previous.read_text())
        if path.read_text() != original:
            raise RuntimeError('VPN configuration changed concurrently. Refresh first.')
        replacing = True
        atomic_write(path, candidate)
        if previous:
            previous.unlink()
    except Exception:
        current = path.read_text()
        if replacing and current == candidate:
            atomic_write(path, original)
        elif replacing and current != original:
            raise RuntimeError('VPN configuration changed during rename recovery. Concurrent edits and protected client exports were preserved; inspect them before retrying.') from None
        destination.unlink(missing_ok=True)
        raise
    return {'renamed': True}


def require_private_socks_engine():
    message = ('Private SOCKS5 requires stable Docker Engine 28.0.0 or newer. '
               'Older localhost publications may be reachable from nearby hosts. '
               'Install/start a supported daemon manually if unavailable; '
               'Ashapp will not upgrade or restart shared Docker automatically.')
    try:
        version = run(['docker', 'version', '--format', '{{.Server.Version}}'], check=False)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError(message) from None
    text = version.stdout.strip()
    parsed = re.fullmatch(r'(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})'
                          r'(?:[-+](?:\d|dfsg|ubuntu|azure|ce)[A-Za-z0-9.+~_-]{0,127})?', text)
    if (version.returncode or not parsed or tuple(map(int, parsed.groups())) < (28, 0, 0)
            or re.search(r'alpha|beta|rc|dev|nightly|test', text, re.I)):
        raise RuntimeError(message)
    return {'private_socks_ready': True}


def socks_publications(inspected):
    # Requested ports may be empty or differ from the allocated runtime port.
    # A stopped container has no runtime publication; inspect its saved binds.
    if inspected.get('State', {}).get('Running') is True:
        return inspected.get('NetworkSettings', {}).get('Ports') or {}
    return inspected.get('HostConfig', {}).get('PortBindings') or {}


def inspect_socks():
    rows = json.loads(run(['docker', 'inspect', '--type', 'container', SOCKS_NAME]).stdout)
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or not isinstance(rows[0].get('Id'), str)
            or not re.fullmatch(r'[a-f0-9]{64}', rows[0]['Id'])):
        raise RuntimeError('The SOCKS5 container identity could not be verified. Refresh before retrying.')
    return rows[0]


def socks_info():
    inspected = inspect_socks()
    identity = inspected['Id']
    proc = run(["docker", "exec", identity, "cat", SOCKS_CONFIG], check=False)
    if proc.returncode:
        raise RuntimeError("Could not read the SOCKS5 configuration.")
    match = re.search(r"(?m)^users ([A-Za-z0-9_]+):CL:([A-Za-z0-9_]+)\s*$", proc.stdout)
    port = re.search(r"(?m)^socks -p([0-9]+)\s*$", proc.stdout)
    if not match or not port:
        raise RuntimeError("The SOCKS5 configuration format is unsupported.")
    bindings = socks_publications(inspected).get(port.group(1) + '/tcp') or []
    ports = {int(item['HostPort']) for item in bindings}
    if len(ports) != 1 or not 1 <= next(iter(ports)) <= 65535:
        raise RuntimeError('The public SOCKS5 port is missing or ambiguous.')
    private = all(ipaddress.ip_address(item.get('HostIp') or '0.0.0.0').is_loopback for item in bindings)
    if private:
        require_private_socks_engine()
    current = inspect_socks()
    if (current['Id'] != identity
            or current.get('State', {}).get('Running') != inspected.get('State', {}).get('Running')
            or socks_publications(current) != socks_publications(inspected)):
        raise RuntimeError('The SOCKS5 container or publication changed while reading access. Refresh before retrying.')
    return {"user": match.group(1), "password": match.group(2), "port": next(iter(ports)),
            'access': 'private' if private else 'public', 'source': SOCKS_NAME, 'container_id': identity}


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError('SOCKS5 closed the connection.')
        data.extend(chunk)
    return bytes(data)


def socks_check():
    info = socks_info()
    user, password = info['user'].encode(), info['password'].encode()
    for attempt in range(10):
        try:
            with socket.create_connection(('127.0.0.1', info['port']), timeout=3) as sock:
                sock.sendall(b'\x05\x01\x02')
                if recv_exact(sock, 2) != b'\x05\x02':
                    raise RuntimeError('SOCKS5 did not request authentication.')
                sock.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
                if recv_exact(sock, 2) != b'\x01\x00':
                    raise RuntimeError('SOCKS5 authentication was rejected.')
                return {'ok': True}
        except OSError:
            if attempt == 9:
                raise RuntimeError('SOCKS5 is unavailable.') from None
            time.sleep(1)


def users():
    import pwd
    return {'users': [{'name': item.pw_name, 'uid': item.pw_uid,
                       'shell': item.pw_shell}
                      for item in pwd.getpwall() if 1000 <= item.pw_uid < 65534]}


def service_control(kind, operation):
    if operation not in ('start', 'stop', 'restart'):
        raise ValueError('Invalid service operation.')
    if kind == 'awg':
        if shared_awg_status().get('configured'):
            if (AWG_DIR / 'params').exists() or any(AWG_DIR.glob('*.conf')):
                raise ValueError('Conflicting host and shared VPN deployments require manual review.')
            return shared_awg_manager().control(shared_awg_backend(), operation)
        params, iface, path, text = settings()
        if run(['pgrep', '-x', 'amneziawg-go'], check=False).returncode == 0:
            raise ValueError('Refusing to manage a userspace VPN.')
        run(['systemctl', operation, 'awg-quick@' + iface])
        if operation != 'stop' and not verified_kernel(iface):
            raise ValueError('The VPN did not start as a kernel interface.')
    elif kind == 'socks':
        if operation != 'stop':
            inspected = json.loads(run(['docker', 'inspect', '--type', 'container', SOCKS_NAME]).stdout)[0]
            if any(ipaddress.ip_address(item.get('HostIp') or '0.0.0.0').is_loopback
                   for bindings in socks_publications(inspected).values() for item in bindings or []):
                require_private_socks_engine()
        run(['docker', operation, SOCKS_NAME])
    else:
        raise ValueError('Invalid service.')
    return {'ok': True}


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Root is required.")
    action = sys.argv[1]
    fields = read_fields()
    lock_path = Path("/run/ashapp/clients.lock")
    if lock_path.parent.is_symlink():
        raise RuntimeError('Unsafe runtime directory.')
    lock_path.parent.mkdir(mode=0o700, exist_ok=True)
    if lock_path.parent.stat().st_uid != 0:
        raise RuntimeError('Unsafe runtime directory owner.')
    lock_path.parent.chmod(0o700)
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == "status":
            result = status()
        elif action == "clients":
            result = list_clients()
        elif action in ('add-client', 'get-client', 'revoke-client', 'rename-client', 'import-client'):
            result = client_action(action, fields)
        elif action == "socks-info":
            result = socks_info()
        elif action == "socks-check":
            result = socks_check()
        elif action == 'socks-private-ready':
            result = require_private_socks_engine()
        elif action == 'users':
            result = users()
        elif action == 'awg-control':
            result = service_control('awg', fields[0])
        elif action == 'socks-control':
            result = service_control('socks', fields[0])
        else:
            raise RuntimeError("Unknown action.")
        emit(result)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, IndexError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)

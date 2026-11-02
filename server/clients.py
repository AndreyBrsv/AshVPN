#!/usr/bin/env python3
"""Root-only AWG management and JSON reporting. No shell interpolation or secret logs."""
from __future__ import annotations

import fcntl
import ipaddress
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

AWG_DIR = Path("/etc/amnezia/amneziawg")
CLIENTS_DIR = Path("/var/lib/ashapp/clients")
SOCKS_NAME = "amnezia-socks5proxy"
SOCKS_CONFIG = "/usr/local/3proxy/conf/3proxy.cfg"
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


def sync(iface, path):
    stripped = run(["awg-quick", "strip", str(path)]).stdout
    run(["awg", "syncconf", iface, "/dev/stdin"], stripped)


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
        state = run(['docker', 'inspect', '--format', '{{json .State}}', name], check=False)
        try:
            value = json.loads(state.stdout) if state.returncode == 0 else None
            if not isinstance(value, dict) or not isinstance(value.get('Running'), bool):
                raise ValueError()
        except (ValueError, TypeError):
            raise RuntimeError('An AmneziaVPN container could not be inspected. Refresh before making changes.') from None
        iface, tool = AMNEZIA_AWG[name]
        found.append({'source': name, 'running': value['Running'],
                      'interface': iface, 'tool': tool})
    return found


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
    result.update(vless_manager().status())
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
        result['external_awg'] = amnezia_containers()
        if result['external_awg']:
            result['awg_configured'] = True
    except RuntimeError as error:
        result['vpn_detection_error'] = str(error)
    if run(["sh", "-c", "command -v docker >/dev/null"], check=False).returncode == 0:
        for name, field, target in ((SOCKS_NAME, "socks5", None),):
            proc = run(["docker", "inspect", name], check=False)
            if proc.returncode == 0:
                obj = json.loads(proc.stdout)[0]
                result[field] = bool(obj["State"]["Running"])
                result[field + '_configured'] = True
                for key, bindings in obj["NetworkSettings"]["Ports"].items():
                    if bindings and (target is None or key == target):
                        result[field + "_port"] = int(bindings[0]["HostPort"])
                        break
    icmp = run(["iptables", "-C", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"], check=False)
    result["icmp_blocked"] = icmp.returncode == 0
    proc = run(["/usr/sbin/sshd", "-T"], check=False)
    result["ssh"] = dict(line.split(None, 1) for line in proc.stdout.splitlines()
                         if line.startswith(("permitrootlogin ", "passwordauthentication ")))
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
    server_addresses = [ipaddress.ip_interface(s.strip()) for s in cfg["Address"].split(",")]
    # Reserve complete routed networks, including peers without a Varckin marker.
    # A peer with /24 AllowedIPs owns that route, not just its first address.
    reserved = []
    for peer in original.split("[Peer]")[1:]:
        for address in assignments(peer).get("AllowedIPs", "").split(","):
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
        atomic_write(path, new)
        sync(iface, path)
    except Exception:
        atomic_write(path, original)
        destination.unlink(missing_ok=True)
        try:
            sync(iface, path)
        except Exception:
            pass
        raise
    return {"name": name, "created": True}


def get_client(name):
    params, iface, path, text = settings()
    blocks = [cfg for item, _, _, cfg in peer_blocks(text) if item == name]
    if len(blocks) != 1:
        raise RuntimeError("Client not found.")
    content = client_path(iface, name).read_bytes().decode('utf-8')
    client_helpers().validate_configuration(content, interface_values(text), blocks[0], blocks[0].get('PublicKey'),
        lambda private: run(['awg', 'pubkey'], private + '\n').stdout.strip())
    return {"name": name, "config": content}


def import_client_configuration(name, public, content, replace=False):
    _, iface, _, text = settings()
    blocks = [cfg for item, _, _, cfg in peer_blocks(text) if item == name]
    if len(blocks) != 1 or blocks[0].get('PublicKey') != public:
        raise RuntimeError('The client identity changed. Refresh first.')
    client_helpers().validate_configuration(content, interface_values(text), blocks[0], public,
        lambda private: run(['awg', 'pubkey'], private + '\n').stdout.strip())
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
    try:
        atomic_write(path, new)
        sync(iface, path)
    except Exception:
        atomic_write(path, original)
        try:
            sync(iface, path)
        except Exception:
            pass
        raise
    try:
        client_path(iface, name).unlink()
    except RuntimeError:
        pass
    return {"revoked": True}


def client_action(action, fields):
    """UI mutations use an explicit source/public key; setup keeps its host-only API."""
    name = fields[0]
    source = fields[1] if len(fields) > 1 else ''
    if source == 'vless-reality':
        return vless_manager().action(action, fields)
    if source in AMNEZIA_AWG:
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
    try:
        if previous:
            atomic_write(destination, previous.read_text())
        atomic_write(path, original[:start] + block + original[end:])
        if previous:
            previous.unlink()
    except Exception:
        atomic_write(path, original)
        destination.unlink(missing_ok=True)
        raise
    return {'renamed': True}


def socks_info():
    proc = run(["docker", "exec", SOCKS_NAME, "cat", SOCKS_CONFIG], check=False)
    if proc.returncode:
        raise RuntimeError("Could not read the SOCKS5 configuration.")
    match = re.search(r"(?m)^users ([A-Za-z0-9_]+):CL:([A-Za-z0-9_]+)\s*$", proc.stdout)
    port = re.search(r"(?m)^socks -p([0-9]+)\s*$", proc.stdout)
    if not match or not port:
        raise RuntimeError("The SOCKS5 configuration format is unsupported.")
    return {"user": match.group(1), "password": match.group(2), "port": int(port.group(1))}


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
        params, iface, path, text = settings()
        if run(['pgrep', '-x', 'amneziawg-go'], check=False).returncode == 0:
            raise ValueError('Refusing to manage a userspace VPN.')
        run(['systemctl', operation, 'awg-quick@' + iface])
        if operation != 'stop' and not verified_kernel(iface):
            raise ValueError('The VPN did not start as a kernel interface.')
    elif kind == 'socks':
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

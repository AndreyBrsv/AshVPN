#!/usr/bin/env python3
"""Configured kernel setup using the checksum-pinned Varckin package routine.

No terminal answers are synthesized. Only the reviewed package-install function
is invoked; Ashapp writes the IPv4-only server configuration and manages peers.
"""
import hashlib
import importlib.util
import ipaddress
import json
import re
import secrets
import os
import socket
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

PIN = '10c9ef9b3b4e9ee4838c06fb8fe89a512a65149f68830dc87fe90f437d2accd4'
PPA_FINGERPRINT = '75C9DD72C799870E310542E24166F2C257290828'
PPA_URL = 'https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu'


def primary_fingerprints(metadata):
    """Select primary fingerprints, never a short ID or a subkey fingerprint."""
    result, awaiting = [], False
    for line in metadata.splitlines():
        fields = line.split(':')
        if fields[0] in ('pub', 'sec'):
            if awaiting or fields[0] == 'sec':
                raise ValueError('Invalid package signing key metadata.')
            awaiting = True
        elif fields[0] == 'sub':
            if awaiting:
                raise ValueError('Missing primary signing fingerprint.')
        elif fields[0] == 'fpr' and awaiting:
            if len(fields) <= 9 or not re.fullmatch('[A-F0-9]{40}', fields[9]):
                raise ValueError('Invalid package signing fingerprint.')
            result.append(fields[9])
            awaiting = False
    if awaiting:
        raise ValueError('Missing primary signing fingerprint.')
    return result


def prepare_ppa(root=Path('/'), fetch=urllib.request.urlopen, command=subprocess.run):
    """Install public, repository-scoped trust after checking the pinned identity."""
    keyring = root / 'usr/share/keyrings/ashapp-amnezia.gpg'
    sources = root / 'etc/apt/sources.list.d'
    source = sources / 'ashapp-amnezia.list'
    content = ''.join(f'{kind} [signed-by=/usr/share/keyrings/ashapp-amnezia.gpg] {PPA_URL} focal main\n'
                      for kind in ('deb', 'deb-src'))
    candidates = [root / 'etc/apt/sources.list', *sources.glob('*.list'), *sources.glob('*.sources')]
    for path in candidates:
        if not path.exists():
            continue
        if path.is_symlink():
            raise ValueError('Review linked APT sources before adding package trust.')
        text = path.read_text(encoding='utf-8')
        if path == source and text == content:
            continue
        if path == source:
            raise ValueError('The dedicated Amnezia APT source is occupied. Review it before setup.')
        if any('ppa.launchpadcontent.net/amnezia/ppa' in line.split('#', 1)[0]
               or 'ppa.launchpad.net/amnezia/ppa' in line.split('#', 1)[0]
               for line in text.splitlines()):
            raise ValueError('Review existing Amnezia APT sources before adding scoped package trust.')
    with tempfile.TemporaryDirectory(prefix='ashapp-apt-') as folder:
        temporary = Path(folder)
        armored, binary = temporary / 'key.asc', temporary / 'key.gpg'
        url = f'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{PPA_FINGERPRINT}'
        with fetch(url, timeout=30) as response:
            data = response.read(1024 * 1024 + 1)
        if not data or len(data) > 1024 * 1024:
            raise ValueError('Invalid package signing key size.')
        armored.write_bytes(data)
        base = ['gpg', '--no-options', '--batch', '--homedir', str(temporary)]
        result = command([*base, '--with-colons', '--show-keys', str(armored)],
                         check=True, capture_output=True, text=True, timeout=30)
        if primary_fingerprints(result.stdout) != [PPA_FINGERPRINT]:
            raise ValueError('Package signing key fingerprint mismatch. APT trust was not changed.')
        command([*base, '--dearmor', '--output', str(binary), str(armored)],
                check=True, capture_output=True, text=True, timeout=30)
        for path, payload in ((keyring, binary.read_bytes()), (source, content.encode())):
            if path.is_symlink():
                raise ValueError('Unsafe package trust destination.')
            missing = []
            parent = path.parent
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for parent in reversed(missing):
                parent.mkdir(mode=0o755)
                parent.chmod(0o755)
            fd, name = tempfile.mkstemp(prefix='.ashapp-apt-', dir=path.parent)
            try:
                with os.fdopen(fd, 'wb') as output:
                    os.fchmod(output.fileno(), 0o644)
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(name, path)
            finally:
                Path(name).unlink(missing_ok=True)


def package_script(original):
    if hashlib.sha256(original).hexdigest() != PIN:
        raise ValueError('The pinned installer checksum does not match.')
    source = original.decode('utf-8')
    # Preserve the vendor pin while replacing its unsafe Debian trust bootstrap.
    unsafe = ('\t\tapt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828\n'
              '\t\techo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list\n'
              '\t\techo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list\n')
    if source.count(unsafe) != 1:
        raise ValueError('The reviewed Debian package routine changed.')
    helper = str(Path(__file__).resolve())
    import shlex
    source = source.replace(unsafe, '\t\tapt install -y gnupg\n\t\tpython3 ' + shlex.quote(helper) + ' --prepare-ppa\n')
    declarations, tail = source.split('# Check for root, virt, OS...\n', 1)
    start = declarations.index('\t# Install AmneziaWG tools and module\n',
                               declarations.index('function installAmneziaWG() {'))
    end = declarations.index('\n\tSERVER_AWG_CONF=', start)
    body = declarations[start:end]
    # Replace question/config/client functions by invoking the package body only.
    # Exclude inactive vendor management functions from the executed adapter.
    prelude = declarations[:declarations.index('function installAmneziaWG() {')]
    return ('set -Eeuo pipefail\numask 077\n' + prelude +
            '\nfunction installAmneziaWG() {\n' + body +
            '\n}\nfunction apt() { command apt -o Dpkg::Options::=--force-confold "$@"; }\n'
            'initialCheck\ninstallAmneziaWG\n')


def validate(host, port, dns):
    ipaddress.IPv4Address(host)
    ipaddress.IPv4Address(dns)
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid AmneziaWG port.')
    return int(port)


def configure(host, port, dns, nic, private, public):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', nic):
        raise ValueError('Invalid public interface name.')
    headers = secrets.SystemRandom().sample(range(5, 2147483648), 4)
    s1, s2 = secrets.randbelow(136) + 15, secrets.randbelow(136) + 15
    while s1 + 56 == s2:
        s2 = secrets.randbelow(136) + 15
    obfuscation = dict(Jc=secrets.randbelow(8) + 3, Jmin=50, Jmax=1000,
                      S1=s1, S2=s2, **dict(zip(('H1', 'H2', 'H3', 'H4'), headers)))
    values = dict(SERVER_PUB_IP=host, SERVER_PUB_NIC=nic, SERVER_AWG_NIC='awg0',
                  SERVER_AWG_IPV4='10.66.66.1', SERVER_AWG_IPV6='', SERVER_PORT=port,
                  SERVER_PRIV_KEY=private, SERVER_PUB_KEY=public, CLIENT_DNS_1=dns,
                  CLIENT_DNS_2='', ALLOWED_IPS='0.0.0.0/0')
    values.update({'SERVER_AWG_' + key.upper(): value for key, value in obfuscation.items()})
    params = ''.join(f'{key}={value}\n' for key, value in values.items())
    config = (f'[Interface]\nAddress = 10.66.66.1/24\nListenPort = {port}\n'
              f'PrivateKey = {private}\n' +
              ''.join(f'{key} = {value}\n' for key, value in obfuscation.items()))
    rules = [f'INPUT -p udp --dport {port} -j ACCEPT',
             f'FORWARD -i {nic} -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
             'FORWARD -i awg0 -j ACCEPT']
    for rule in rules:
        rule = rule.replace(' -j ', ' -m comment --comment ashapp-awg -j ')
        config += f'PostUp = iptables -A {rule}\nPostDown = iptables -D {rule}\n'
    nat = f'POSTROUTING -m comment --comment ashapp-awg -s 10.66.66.0/24 -o {nic} -j MASQUERADE'
    config += f'PostUp = iptables -t nat -A {nat}\nPostDown = iptables -t nat -D {nat}\n'
    return params, config


def activate_configuration(clients, directory, params, config,
                           forwarding=Path('/etc/sysctl.d/90-ashapp-forwarding.conf')):
    """Roll back only files created by this attempt if activation fails."""
    previous_file = forwarding.read_bytes() if forwarding.exists() else None
    previous_value = clients.run(['sysctl', '-n', 'net.ipv4.ip_forward']).stdout.strip()
    try:
        clients.atomic_write(directory / 'params', params)
        clients.atomic_write(directory / 'awg0.conf', config)
        clients.atomic_write(forwarding, 'net.ipv4.ip_forward = 1\n', 0o644)
        clients.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        clients.run(['systemctl', 'enable', '--now', 'awg-quick@awg0'])
        if not clients.verified_kernel('awg0'):
            raise ValueError('The resulting interface is not a kernel AmneziaWG interface.')
    except BaseException:
        clients.run(['systemctl', 'disable', '--now', 'awg-quick@awg0'], check=False)
        (directory / 'params').unlink(missing_ok=True)
        (directory / 'awg0.conf').unlink(missing_ok=True)
        if previous_file is None:
            forwarding.unlink(missing_ok=True)
        else:
            clients.atomic_write(forwarding, previous_file.decode(), 0o644)
        if previous_value in ('0', '1'):
            clients.run(['sysctl', '-w', f'net.ipv4.ip_forward={previous_value}'], check=False)
        raise


def main(arguments=()):
    if os.geteuid() != 0:
        raise ValueError('Kernel setup requires root.')
    if list(arguments) == ['--prepare-ppa']:
        prepare_ppa()
        return
    if arguments:
        raise ValueError('Unknown kernel setup operation.')
    base = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('clients', base / 'clients.py')
    clients = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(clients)
    policy_spec = importlib.util.spec_from_file_location('ashapp_firewall_policy', base / 'firewall_policy.py')
    policy = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy)
    fields = clients.read_fields()
    if len(fields) != 3:
        raise ValueError('Expected an IPv4 address, UDP port and DNS address.')
    host, raw_port, dns = fields
    port = validate(host, raw_port, dns)
    directory = clients.AWG_DIR
    if clients.amnezia_containers():
        raise ValueError('An existing AmneziaVPN Docker deployment was found. It will not be replaced.')
    if (directory / 'params').exists() or any(directory.glob('*.conf')):
        raise ValueError('AmneziaWG is already configured; use server management.')
    if clients.run(['pgrep', '-x', 'amneziawg-go'], check=False).returncode == 0:
        raise ValueError('A userspace AmneziaWG process is running.')
    if clients.run(['systemctl', 'is-active', '--quiet', 'firewalld'], check=False).returncode == 0:
        raise ValueError('Configured setup requires iptables; firewalld is active.')
    policy.check_install_policy(clients.run, ('INPUT', 'FORWARD'))
    routes = json.loads(clients.run(['ip', '-j', '-4', 'route', 'show', 'default']).stdout)
    if not routes or not routes[0].get('dev'):
        raise ValueError('No default IPv4 route was found.')
    nic = routes[0]['dev']
    for route in json.loads(clients.run(['ip', '-j', '-4', 'route', 'show']).stdout):
        dest = route.get('dst', 'default')
        if dest != 'default' and ipaddress.ip_network(dest, strict=False).overlaps(ipaddress.ip_network('10.66.66.0/24')):
            raise ValueError('The VPN subnet 10.66.66.0/24 overlaps an existing route.')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(('0.0.0.0', port))
    script = package_script((base / 'amneziawg-install.sh').read_bytes())
    # Debian cloud images may use deb822 sources without a sources.list file.
    sources = Path('/etc/apt/sources.list')
    sources.touch(exist_ok=True)
    deb822 = Path('/etc/apt/sources.list.d/debian.sources')
    if deb822.exists():
        content = deb822.read_text()
        if 'deb-src' not in content:
            clients.atomic_write(Path('/etc/apt/sources.list.d/ashapp-debian-src.sources'),
                                 content.replace('Types: deb', 'Types: deb deb-src'), 0o644)
    subprocess.run(['bash', '-c', script], check=True)
    clients.run(['modprobe', 'amneziawg'])
    if not Path('/sys/module/amneziawg').exists():
        raise ValueError('The AmneziaWG kernel module did not load.')
    private = clients.run(['awg', 'genkey']).stdout.strip()
    public = clients.run(['awg', 'pubkey'], private + '\n').stdout.strip()
    params, config = configure(host, port, dns, nic, private, public)
    activate_configuration(clients, directory, params, config)
    clients.emit({'installed': True, 'awg_port': port})


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, RuntimeError) as error:
        # Never print configs, private keys, command input or package command output.
        print('ERROR: configured kernel setup failed: ' + str(error) if not isinstance(error, subprocess.CalledProcessError)
              else 'ERROR: the pinned kernel package installer failed.', file=sys.stderr)
        sys.exit(1)

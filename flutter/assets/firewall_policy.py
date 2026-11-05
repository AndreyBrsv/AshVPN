"""Conservative preflight for new listeners; never widen an external policy."""
import shlex
import importlib.util
from pathlib import Path


def security_policy():
    spec = importlib.util.spec_from_file_location('ashapp_install_security', Path(__file__).with_name('security_manager.py'))
    security = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(security)
    security.check_owned()
    return security


def managed_firewall():
    security = security_policy()
    return 'firewall' in security.owned() and not (security.STATE / 'pending.json').exists()


def rule_options(words):
    """Accept only the narrow match syntax emitted by our protection rules."""
    if len(words) % 2:
        return {}, set()
    options, modules = {}, set()
    for key, value in zip(words[::2], words[1::2]):
        if key == '-m':
            if value in modules:
                return {}, set()
            modules.add(value)
        elif key in options:
            return {}, set()
        else:
            options[key] = value
    return options, modules


def owned_protection(words):
    if words[:2] != ['-A', 'INPUT']:
        return False
    options, modules = rule_options(words[2:])
    if (set(options) == {'-p', '--icmp-type', '--comment', '-j'}
            and modules <= {'icmp', 'comment'} and 'comment' in modules
            and options['-p'] == 'icmp' and options['--icmp-type'] in ('8', '8/0', 'echo-request')
            and options['--comment'] == 'ashapp-owned-icmp-v1' and options['-j'] == 'DROP'):
        return True
    if (set(options) == {'-p', '--dports', '-j'} and modules <= {'tcp', 'multiport'}
            and 'multiport' in modules and options['-p'] == 'tcp' and options['-j'] == 'f2b-ashapp-sshd'):
        ports = options['--dports'].split(',')
        if not all(port.isdecimal() for port in ports):
            return False
        security = security_policy()
        return ('fail2ban' in security.owned() and not (security.STATE / 'pending.json').exists()
                and set(map(int, ports)) == set(security.ssh_ports()))
    return False


def check_install_policy(command, chains=('INPUT',)):
    for service in ('firewalld', 'nftables'):
        if command(['systemctl', 'is-active', '--quiet', service], check=False).returncode == 0:
            raise RuntimeError('An external firewall requires manual review before installing a VPN listener.')
    ufw = command(['ufw', 'status'], check=False)
    if ufw.stdout.startswith('Status: active'):
        raise RuntimeError('Active UFW requires manual review before installing a VPN listener.')
    for chain in chains:
        result = command(['iptables', '-S', chain], check=False)
        if result.returncode or f'-P {chain} ACCEPT' not in result.stdout.splitlines():
            raise RuntimeError('Existing restrictive firewall policy requires manual review before VPN installation.')
        for line in result.stdout.splitlines():
            words = shlex.split(line)
            if words[:2] != ['-A', chain]:
                continue
            if owned_protection(words):
                continue
            # Appended service rules retain these owned protection chains ahead
            # of them; the reviewed protection refresh opens the new listener.
            target = words[words.index('-j') + 1] if '-j' in words else None
            if target == 'ASHAPP-IN' and not managed_firewall():
                raise RuntimeError('An unowned or pending firewall requires manual review before VPN installation.')
            if target not in ('ACCEPT', 'LOG', 'NFLOG', 'ASHAPP-IN'):
                raise RuntimeError('Existing firewall restrictions require manual review before VPN installation.')

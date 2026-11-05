"""Firewall installation preflight with synthetic policies, without packet filtering."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('firewall_policy', ROOT / 'server/firewall_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class FirewallPolicyTests(unittest.TestCase):
    def test_own_ping_and_verified_ssh_protection_allow_both_vpn_install_paths(self):
        owned_ping = '-A INPUT -p icmp -m comment --comment ashapp-owned-icmp-v1 -m icmp --icmp-type 8 -j DROP\n'
        owned_ssh = '-A INPUT -p tcp -m multiport --dports 2222,22 -j f2b-ashapp-sshd\n'
        security = SimpleNamespace(owned=lambda: {'fail2ban': 'fixture-hash'}, STATE=ROOT / 'missing-fixture-state', ssh_ports=lambda: [22, 2222])
        for chains in (('INPUT',), ('INPUT', 'FORWARD')):
            def run(args, check=True):
                if args[:2] == ['iptables', '-S']:
                    return SimpleNamespace(returncode=0, stdout='-P ' + args[2] + ' ACCEPT\n' + (owned_ping + owned_ssh if args[2] == 'INPUT' else ''))
                return SimpleNamespace(returncode=3, stdout='')
            with self.subTest(chains=chains), patch.object(policy, 'security_policy', return_value=security):
                policy.check_install_policy(run, chains)

    def test_protection_exceptions_do_not_accept_foreign_or_broadened_rules(self):
        security = SimpleNamespace(owned=lambda: {'fail2ban': 'fixture-hash'}, STATE=ROOT / 'missing-fixture-state', ssh_ports=lambda: [2222])
        rules = [
            '-A INPUT -p icmp --icmp-type 8 -j DROP',
            '-A INPUT -p tcp -m comment --comment ashapp-owned-icmp-v1 --dport 443 -j DROP',
            '-A INPUT -p tcp -m multiport --dports 443 -j f2b-ashapp-sshd',
            '-A INPUT -p tcp -j f2b-ashapp-sshd',
            '-A INPUT -p tcp -m multiport --dports 2222 -j f2b-foreign',
        ]
        with patch.object(policy, 'security_policy', return_value=security):
            for rule in rules:
                with self.subTest(rule=rule), self.assertRaisesRegex(RuntimeError, 'manual review'):
                    policy.check_install_policy(self.command('-P INPUT ACCEPT\n' + rule + '\n'))
        security.owned = lambda: {}
        with patch.object(policy, 'security_policy', return_value=security), self.assertRaisesRegex(RuntimeError, 'manual review'):
            policy.check_install_policy(self.command('-P INPUT ACCEPT\n-A INPUT -p tcp -m multiport --dports 2222 -j f2b-ashapp-sshd\n'))

    def command(self, text):
        def run(args, check=True):
            if args[:2] == ['iptables', '-S']:
                return SimpleNamespace(returncode=0, stdout=text)
            return SimpleNamespace(returncode=3, stdout='')
        return run

    def test_source_restrictions_and_unknown_jumps_are_refused(self):
        for text in ('-P INPUT DROP\n', '-P INPUT ACCEPT\n-A INPUT -p tcp --dport 443 -j DROP\n',
                     '-P INPUT ACCEPT\n-A INPUT -j EXTERNAL\n'):
            with self.subTest(text=text), self.assertRaisesRegex(RuntimeError, 'manual review'):
                policy.check_install_policy(self.command(text))

    def test_unrestricted_and_owned_protection_preserve_precedence(self):
        with patch.object(policy, 'managed_firewall', return_value=True):
            policy.check_install_policy(self.command('-P INPUT ACCEPT\n-A INPUT -j ASHAPP-IN\n'))
        with patch.object(policy, 'managed_firewall', return_value=False), self.assertRaisesRegex(RuntimeError, 'manual review'):
            policy.check_install_policy(self.command('-P INPUT ACCEPT\n-A INPUT -j ASHAPP-IN\n'))
        self.assertNotIn('iptables -I', (ROOT / 'server/awg_setup.py').read_text())
        self.assertNotIn('iptables -I', (ROOT / 'server/vless_manager.py').read_text())


if __name__ == '__main__':
    unittest.main()

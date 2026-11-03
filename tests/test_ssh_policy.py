"""Exercise only the pure SSH-policy inspector, never sshd or real /etc files."""
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'server/remote.sh').read_text(encoding='utf-8')
POLICY = SOURCE.split("<<'SSH_POLICY'\n", 1)[1].split('\nSSH_POLICY', 1)[0]
namespace = {'__name__': 'ssh_policy_fixture'}
exec(compile(POLICY, 'ssh-policy-inspector', 'exec'), namespace)


class SshPolicyTests(unittest.TestCase):
    def inspect(self, text, includes=None):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for name, contents in (includes or {}).items():
                target = base / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(contents, encoding='utf-8')
            config = base / 'sshd_config'
            config.write_text(text, encoding='utf-8')
            namespace['check_config'](config, base=base)

    def test_default_global_policy_and_optional_empty_glob_are_accepted(self):
        self.inspect('Include "sshd_config.d/*.conf"\n# Match Address ignored\nPermitRootLogin yes\n')

    def test_other_address_match_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Conditional'):
            self.inspect('PermitRootLogin no\nMatch Address 198.51.100.99\n PermitRootLogin yes\n')

    def test_nested_includes_case_quotes_and_equals_cannot_hide_match(self):
        for directive in ('iNcLuDe="parts/*.conf"', 'Include = "parts/*.conf"', 'Include ="parts/*.conf"'):
            with self.subTest(directive=directive), self.assertRaisesRegex(ValueError, 'Conditional'):
                self.inspect(directive + '\n', {'parts/one.conf': 'Include nested.conf\n',
                                              'nested.conf': 'mAtCh=Address 198.51.100.99\nPermitRootLogin yes\n'})

    def test_cycle_missing_include_and_ambiguous_syntax_fail_closed(self):
        for text, files in [('Include cycle.conf\n', {'cycle.conf': 'Include sshd_config\n'}),
                            ('Include missing.conf\n', {}), ('Include "unterminated\n', {}),
                            ('Include ${UNKNOWN}/file\n', {})]:
            with self.subTest(text=text), self.assertRaises((OSError, ValueError)):
                self.inspect(text, files)

    def test_libc_glob_classes_cannot_be_silently_skipped_by_python_glob(self):
        for pattern in ('[[:digit:]]*.conf', '[0-9]*.conf', '{10,20}-conditional.conf'):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, 'Unsupported'):
                self.inspect('Include parts/' + pattern + '\n',
                             {'parts/10-conditional.conf': 'Match Address 198.51.100.99\nPermitRootLogin yes\n'})

    def test_guard_precedes_backup_and_configuration_mutations(self):
        body = SOURCE.split('ssh_config() {', 1)[1].split('\nssh_policy_without_match()', 1)[0]
        self.assertLess(body.index('ssh_policy_without_match /etc/ssh/sshd_config'),
                        body.index('cp -a -- /etc/ssh/sshd_config'))


if __name__ == '__main__':
    unittest.main()

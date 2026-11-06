import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AssetTests(unittest.TestCase):
    def test_server_sources_match_flutter_bundles(self):
        for name in ("remote.sh", "clients.py", "awg_setup.py", "amnezia_setup.py", "amnezia_clients.py", "vless_manager.py", "security_manager.py", "firewall_policy.py"):
            with self.subTest(name=name):
                self.assertEqual((ROOT / "server" / name).read_bytes(),
                                 (ROOT / "flutter" / "assets" / name).read_bytes())

    def test_original_installer_matches_bundle_and_pinned_checksum(self):
        installer = (ROOT / "vendor" / "amneziawg-install.sh").read_bytes()
        self.assertEqual(installer, (ROOT / "flutter" / "assets" / "amneziawg-install.sh").read_bytes())
        backend = (ROOT / "server" / "remote.sh").read_text(encoding="utf-8")
        checksum = re.search(r"'([0-9a-f]{64})'", backend).group(1)
        self.assertEqual(hashlib.sha256(installer).hexdigest(), checksum)


if __name__ == "__main__":
    unittest.main()

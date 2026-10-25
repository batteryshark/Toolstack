"""Real legacy envelope regression; fixture generated with pinned cryptography 45.0.7."""
import json
from pathlib import Path
import tempfile
import unittest

from sps.plugins.localfile import _Vault


class LegacyVaultCompatibility(unittest.TestCase):
    def test_read_update_reopen_legacy_envelope(self):
        fixture = Path(__file__).with_name("vault-45.0.7.json")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            path.write_bytes(fixture.read_bytes())
            path.chmod(0o600)
            original = json.loads(path.read_text())
            vault = _Vault(path, "fake-compatibility-passphrase")
            self.assertEqual(vault.get("fake-tool", "token"), "fake-old-value")
            self.assertEqual(vault.get("fake-tool", "retained"), "fake-retained")
            vault.set("fake-tool", "token", "fake-updated-value")
            reopened = _Vault(path, "fake-compatibility-passphrase")
            self.assertEqual(reopened.get("fake-tool", "token"), "fake-updated-value")
            self.assertEqual(reopened.get("fake-tool", "retained"), "fake-retained")
            updated = json.loads(path.read_text())
            for key in ("version", "kdf", "salt", "n", "r", "p"):
                self.assertEqual(original[key], updated[key])
            self.assertNotEqual(original["ciphertext"], updated["ciphertext"])


if __name__ == "__main__":
    unittest.main()

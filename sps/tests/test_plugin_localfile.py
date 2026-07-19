"""plugins/localfile: encrypted vault round trip."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sps.config import LocalFileBlock
from sps.plugins.localfile import LocalFilePlugin, _Vault


class EncryptedVault(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_round_trip(self):
        vault_path = self.tmp / "vault.json"
        _Vault.init(str(vault_path), "test-passphrase")
        vault = _Vault(str(vault_path), "test-passphrase")
        vault.set("echo", "API_KEY", "V-1")
        self.assertEqual(vault.get("echo", "API_KEY"), "V-1")
        # Reopen and verify the new value persists.
        vault2 = _Vault(str(vault_path), "test-passphrase")
        self.assertEqual(vault2.get("echo", "API_KEY"), "V-1")

    def test_plugin_round_trip(self):
        vault_path = self.tmp / "vault.json"
        _Vault.init(str(vault_path), "test-passphrase")
        _Vault(str(vault_path), "test-passphrase").set("echo", "API_KEY", "V-1")
        plugin = LocalFilePlugin(LocalFileBlock(vault_file=str(vault_path)),
                                passphrase="test-passphrase")
        plugin.connect()
        self.assertEqual(plugin.get_secret("API_KEY", "echo"), "V-1")
        plugin.write_secret("API_KEY", "echo", "V-2")
        self.assertEqual(plugin.get_secret("API_KEY", "echo"), "V-2")

    def test_missing_secret_raises_keyerror(self):
        vault_path = self.tmp / "vault.json"
        _Vault.init(str(vault_path), "p")
        plugin = LocalFilePlugin(LocalFileBlock(vault_file=str(vault_path)),
                                passphrase="p")
        plugin.connect()
        with self.assertRaises(KeyError):
            plugin.get_secret("API_KEY", "echo")

    def test_wrong_passphrase_raises_runtime_error(self):
        vault_path = self.tmp / "vault.json"
        _Vault.init(str(vault_path), "right")
        with self.assertRaises(RuntimeError):
            _Vault(str(vault_path), "wrong")

    def test_list_fields(self):
        vault_path = self.tmp / "vault.json"
        _Vault.init(str(vault_path), "p")
        vault = _Vault(str(vault_path), "p")
        vault.set("echo", "A", "1")
        vault.set("echo", "B", "2")
        self.assertEqual(sorted(vault.list_fields("echo")), ["A", "B"])


if __name__ == "__main__":
    unittest.main()

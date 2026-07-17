"""plugins/localfile: encrypted vault round trip."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sps.config import LocalFileBlock
from sps.plugins.localfile import LocalFilePlugin


class EncryptedVault(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_round_trip(self):
        from toolyard.secrets import VaultBackend  # noqa: E402
        vault_path = self.tmp / "vault.json"
        VaultBackend.init(str(vault_path), "test-passphrase")
        VaultBackend(str(vault_path), "test-passphrase").set_secret("echo", "API_KEY", "V-1")

        block = LocalFileBlock(vault_file=str(vault_path))
        plugin = LocalFilePlugin(block, passphrase="test-passphrase")
        plugin.connect()
        self.assertEqual(plugin.get_secret("API_KEY", "echo"), "V-1")
        plugin.write_secret("API_KEY", "echo", "V-2")

        # Reopen and verify the new value persists.
        plugin2 = LocalFilePlugin(block, passphrase="test-passphrase")
        plugin2.connect()
        self.assertEqual(plugin2.get_secret("API_KEY", "echo"), "V-2")

    def test_missing_secret_raises_keyerror(self):
        from toolyard.secrets import VaultBackend  # noqa: E402
        vault_path = self.tmp / "vault.json"
        VaultBackend.init(str(vault_path), "p")
        plugin = LocalFilePlugin(LocalFileBlock(vault_file=str(vault_path)), passphrase="p")
        plugin.connect()
        with self.assertRaises(KeyError):
            plugin.get_secret("API_KEY", "echo")

"""plugins/localfile: encrypted vault round trip."""
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from sps.config import LocalFileBlock
from sps.plugins.localfile import LocalFilePlugin, _Vault, _vault_passphrase


class PassphraseFile(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.key = self.tmp / "fake.key"
        self.key.write_text("  generated-fake-value\n", encoding="utf-8")
        self.key.chmod(0o600)

    def read_key(self, path=None, direct=None):
        env = {"SP_VAULT_PASSPHRASE_FILE": str(path or self.key)}
        if direct is not None:
            env["SP_VAULT_PASSPHRASE"] = direct
        with patch.dict(os.environ, env, clear=True):
            return _vault_passphrase()

    def test_private_file_and_empty_direct_fallback(self):
        self.assertEqual(self.read_key(), "generated-fake-value")
        self.assertEqual(self.read_key(direct=""), "generated-fake-value")
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_direct_precedence_does_not_lookup_file(self):
        with patch("sps.plugins.localfile.read_private") as reader:
            self.assertEqual(self.read_key(direct=" direct value "), " direct value ")
            reader.assert_not_called()

    def assert_refused_before_open(self, path):
        # Proves no content read or FIFO open (which could otherwise hang).
        with patch("sps.paths.os.open") as opener:
            with self.assertRaises(PermissionError):
                self.read_key(path)
            opener.assert_not_called()

    def test_public_mode_refused_without_repair(self):
        self.key.chmod(0o644)
        self.assert_refused_before_open(self.key)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o644)

    def test_symlink_refused(self):
        link = self.tmp / "linked.key"
        link.symlink_to(self.key)
        self.assert_refused_before_open(link)
        self.assertTrue(link.is_symlink())
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_hardlink_refused(self):
        link = self.tmp / "hard.key"
        os.link(self.key, link)
        self.assert_refused_before_open(link)
        self.assertEqual(self.key.stat().st_nlink, 2)

    def test_fifo_refused(self):
        fifo = self.tmp / "fifo.key"
        os.mkfifo(fifo, 0o600)
        self.assert_refused_before_open(fifo)

    def test_foreign_owner_refused(self):
        original = Path.lstat

        def fake_owner(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == self.key:
                fields = list(info)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return info

        with patch.object(Path, "lstat", fake_owner):
            self.assert_refused_before_open(self.key)
        self.assertEqual(self.key.stat().st_uid, os.getuid())

    def test_linked_parent_refused(self):
        link = self.tmp / "linked-parent"
        link.symlink_to(self.tmp, target_is_directory=True)
        self.assert_refused_before_open(link / self.key.name)

    def test_nonprivate_parent_refused_without_repair(self):
        self.tmp.chmod(0o755)
        self.assert_refused_before_open(self.key)
        self.assertEqual(self.tmp.stat().st_mode & 0o777, 0o755)

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            self.read_key(self.tmp / "missing.key")

    def test_empty_file_generic_error(self):
        self.key.write_text(" \n", encoding="utf-8")
        with self.assertRaises(ValueError) as raised:
            self.read_key()
        self.assertEqual(str(raised.exception), "vault passphrase file is empty")


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

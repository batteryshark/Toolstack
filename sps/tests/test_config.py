"""config: sps.env parsing + mode-0600 enforcement."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from sps.config import (
    Config,
    ConfigModeError,
    InfisicalBlock,
    LocalFileBlock,
    VaultBlock,
    load_config,
)


class ConfigMode(unittest.TestCase):
    def _write(self, content: str, mode: int) -> Path:
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(content)
        f.close()
        p = Path(f.name)
        os.chmod(p, mode)
        return p

    def test_rejects_non_0600_mode(self):
        p = self._write("SP_SECRET=x\n", 0o644)
        self.addCleanup(os.unlink, p)
        with self.assertRaises(ConfigModeError):
            load_config(str(p))

    def test_rejects_0700_mode(self):
        p = self._write("SP_SECRET=x\n", 0o700)
        self.addCleanup(os.unlink, p)
        with self.assertRaises(ConfigModeError):
            load_config(str(p))

    def test_rejects_0707_mode(self):
        p = self._write("SP_SECRET=x\n", 0o707)
        self.addCleanup(os.unlink, p)
        with self.assertRaises(ConfigModeError):
            load_config(str(p))

    def test_loads_0600(self):
        p = self._write(
            'SP_HOST = "127.0.0.1"\n'
            'SP_PORT = "8743"\n'
            'SP_SECRET = "abc"\n'
            'SP_TLS_CERT = "/etc/toolstack/sps.crt"\n'
            'SP_TLS_KEY = "/etc/toolstack/sps.key"\n'
            'SP_TLS_CA = "/etc/toolstack/sps-ca.crt"\n'
            'SP_AUDIT_LOG = "/var/log/sps.audit"\n'
            'SP_PLUGIN = "infisical"\n',
            0o600,
        )
        self.addCleanup(os.unlink, p)
        cfg = load_config(str(p))
        self.assertEqual(cfg.sp_secret, "abc")
        self.assertEqual(cfg.sp_host, "127.0.0.1")
        self.assertEqual(cfg.sp_port, 8743)
        self.assertEqual(cfg.sp_plugin, "infisical")
        self.assertIsNone(cfg.infisical)  # no [infisical] block in this env file


class PluginBlocks(unittest.TestCase):
    def test_infisical_block(self):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(
            'SP_HOST = "h"\nSP_PORT = "1"\nSP_SECRET = "s"\n'
            'SP_TLS_CERT = "c"\nSP_TLS_KEY = "k"\nSP_TLS_CA = "a"\n'
            'SP_PLUGIN = "infisical"\n\n'
            '[infisical]\n'
            'HOST = "https://i"\nVAULT = "V"\nENVIRONMENT = "staging"\n'
        )
        f.close()
        os.chmod(f.name, 0o600)
        self.addCleanup(os.unlink, f.name)
        cfg = load_config(f.name)
        self.assertIsNotNone(cfg.infisical)
        self.assertEqual(cfg.infisical.host, "https://i")  # type: ignore[union-attr]
        self.assertEqual(cfg.infisical.environment, "staging")  # type: ignore[union-attr]

    def test_vault_block(self):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(
            'SP_HOST = "h"\nSP_PORT = "1"\nSP_SECRET = "s"\n'
            'SP_TLS_CERT = "c"\nSP_TLS_KEY = "k"\nSP_TLS_CA = "a"\n'
            'SP_PLUGIN = "hashicorp_vault"\n\n'
            '[hashicorp_vault]\nURL = "https://v"\nTOKEN = "t"\nMOUNT = "kv"\n'
        )
        f.close()
        os.chmod(f.name, 0o600)
        self.addCleanup(os.unlink, f.name)
        cfg = load_config(f.name)
        self.assertIsNotNone(cfg.vault)
        self.assertEqual(cfg.vault.mount, "kv")  # type: ignore[union-attr]

    def test_localfile_block(self):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(
            'SP_HOST = "h"\nSP_PORT = "1"\nSP_SECRET = "s"\n'
            'SP_TLS_CERT = "c"\nSP_TLS_KEY = "k"\nSP_TLS_CA = "a"\n'
            'SP_PLUGIN = "localfile"\n\n'
            '[localfile]\nVAULT_FILE = "/var/lib/sps.vault.json"\n'
        )
        f.close()
        os.chmod(f.name, 0o600)
        self.addCleanup(os.unlink, f.name)
        cfg = load_config(f.name)
        self.assertIsNotNone(cfg.localfile)
        self.assertEqual(cfg.localfile.vault_file, "/var/lib/sps.vault.json")  # type: ignore[union-attr]


class UnknownPlugin(unittest.TestCase):
    def test_rejects_unknown_plugin_name(self):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(
            'SP_HOST = "h"\nSP_PORT = "1"\nSP_SECRET = "s"\n'
            'SP_TLS_CERT = "c"\nSP_TLS_KEY = "k"\nSP_TLS_CA = "a"\n'
            'SP_PLUGIN = "foo"\n'
        )
        f.close()
        os.chmod(f.name, 0o600)
        self.addCleanup(os.unlink, f.name)
        with self.assertRaises(ValueError):
            load_config(f.name)

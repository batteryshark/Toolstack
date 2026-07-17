"""plugins/loader: one-plugin-at-startup dispatch."""
import os
import tempfile
import unittest
from pathlib import Path

from sps.config import Config, InfisicalBlock, VaultBlock
from sps.plugins.loader import load_plugin


def _make_config(**overrides) -> Config:
    base = dict(
        sp_host="x", sp_port=1, sp_secret="s",
        sp_tls_cert="c", sp_tls_key="k", sp_tls_ca="a",
        sp_audit_log="/tmp/sps.audit", sp_plugin="infisical",
        infisical=InfisicalBlock(host="https://x", vault="V",
                                  environment="prod", client_id="i",
                                  client_secret="s"),
        vault=None, localfile=None,
    )
    base.update(overrides)
    return Config(**base)


class Load(unittest.TestCase):
    def test_loads_infisical(self):
        cfg = _make_config()
        plugin = load_plugin(cfg)
        self.assertEqual(plugin.__class__.__name__, "InfisicalPlugin")

    def test_loads_vault(self):
        cfg = _make_config(
            sp_plugin="hashicorp_vault",
            infisical=None,
            vault=VaultBlock(url="https://v", token="T-1", mount="secret"),
        )
        plugin = load_plugin(cfg)
        self.assertEqual(plugin.__class__.__name__, "HashicorpVaultPlugin")

    def test_loads_localfile(self):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.close(); os.unlink(f.name)
        cfg = _make_config(
            sp_plugin="localfile",
            infisical=None,
        )
        from sps.config import LocalFileBlock
        cfg = Config(
            **{**cfg.__dict__, "localfile": LocalFileBlock(vault_file=f.name)}
        )
        plugin = load_plugin(cfg)
        self.assertEqual(plugin.__class__.__name__, "LocalFilePlugin")

    def test_unknown_plugin_name_rejected(self):
        cfg = _make_config(sp_plugin="unknown")
        with self.assertRaises(ValueError):
            load_plugin(cfg)

    def test_plugin_block_missing_rejected(self):
        cfg = _make_config(sp_plugin="infisical", infisical=None)
        with self.assertRaises(ValueError):
            load_plugin(cfg)

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from toolyard import runner, sps_config
from admin.sps_link import SPSLink


class RegistrationConfiguration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "sps.env"
        self.path.write_text('SP_HOST="localhost"\nSP_PORT="8743"\nSP_SECRET="fixture"\n'
                             'SP_TLS_CA="ca.pem"\nSP_PLUGIN="unused"\n'
                             '[vault]\nTOKEN="provider-fixture"\n')
        self.path.chmod(0o600)

    def test_only_registration_values_are_decoded(self):
        original = sps_config.tomllib.loads
        with patch.object(sps_config.tomllib, "loads", wraps=original) as decode:
            cfg = sps_config.load_registration_config(self.path)
        self.assertEqual(cfg.sp_host, "localhost")
        self.assertEqual(cfg.sp_port, 8743)
        self.assertNotIn("fixture", repr(cfg))
        parsed = "\n".join(call.args[0] for call in decode.call_args_list)
        self.assertNotIn("provider-fixture", parsed)
        self.assertNotIn("SP_PLUGIN", parsed)

    def test_ignored_multiline_value_cannot_spoof_registration(self):
        self.path.write_text("IGNORED='''\nSP_HOST=\"wrong\"\n'''\n"
                             'SP_HOST="right"\nSP_PORT="8743"\nSP_SECRET="fixture"\n')
        self.assertEqual(sps_config.load_registration_config(self.path).sp_host, "right")

    def test_quoted_keys_comments_and_multiline_strings(self):
        self.path.write_text('# comment\n"SP_HOST" = "localhost" # comment\n'
                             "SP_PORT='8743'\nSP_SECRET='''fixture\nvalue'''\n")
        self.assertEqual(sps_config.load_registration_config(self.path).sp_secret, "fixture\nvalue")

    def test_private_mode_required(self):
        self.path.chmod(0o644)
        with self.assertRaises(sps_config.ConfigModeError):
            sps_config.load_registration_config(self.path)

    def test_both_clients_use_registration_loader_and_dev_gate(self):
        with patch.dict(os.environ, {}, clear=True), patch("sps.config.load_config", side_effect=AssertionError):
            self.assertTrue(runner._resolve_sps(str(self.path)).verify)
            self.assertTrue(SPSLink.from_env(str(self.path)).verify)
        with patch.dict(os.environ, {"TOOLSTACK_SPS_VERIFY": "0"}, clear=True):
            with self.assertRaises(runner.RunnerConfigError):
                runner._resolve_sps(str(self.path))
            self.assertIsNone(SPSLink.from_env(str(self.path)))
        with patch.dict(os.environ, {"TOOLSTACK_SPS_VERIFY": "0", "TOOLSTACK_SPS_DEV": "1"}, clear=True):
            self.assertFalse(runner._resolve_sps(str(self.path)).verify)
            self.assertFalse(SPSLink.from_env(str(self.path)).verify)

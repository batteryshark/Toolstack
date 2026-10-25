"""Pure fake regressions; no listeners or upstream calls."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from toolstack_forwarder.config import load_config
from toolstack_forwarder.server import _handler


class ChannelTests(unittest.TestCase):
    def test_channel_required_no_sps_fallback(self):
        # Handler construction does not bind a socket.
        handler = object.__new__(_handler(None, None, 1, 1024))
        handler.headers = {"X-Toolstack-Secret": "sps-key"}
        with patch.dict(os.environ, {"TOOLSTACK_E_SECRET": "sps-key"}, clear=True):
            self.assertFalse(handler._verify_channel_secret()[0])
        with patch.dict(os.environ, {"TOOLSTACK_CHANNEL_SECRET": "channel-key"}, clear=True):
            self.assertFalse(handler._verify_channel_secret()[0])
            handler.headers["X-Toolstack-Secret"] = "channel-key"
            self.assertTrue(handler._verify_channel_secret()[0])

    def test_login_sample_redacted(self):
        cfg = load_config(Path(__file__).resolve().parents[2] / "tools/rest_demo/toolyard.toml")
        self.assertTrue(cfg.operations["login"].redact_response_body)
        self.assertTrue(cfg.operations["login"].redact_response_headers)

    def test_writeback_requires_explicit_visibility(self):
        source = Path(__file__).resolve().parents[2] / "tools/rest_demo/toolyard.toml"
        text = source.read_text().replace("redact_response_body = true\n", "")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "toolyard.toml"
            path.write_text(text)
            with self.assertRaisesRegex(ValueError, "writeback requires explicit"):
                load_config(path)

"""Tool environment and log paths remain constrained before launch."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock

from toolyard import runner


class LogGuards(unittest.TestCase):
    def test_tunnel_default_and_explicit_ports_checked_before_connect(self):
        from toolyard.egress_proxy import _handler
        for authority, allow, permitted in (
            ("fake.invalid:443", {"fake.invalid"}, True),
            ("fake.invalid:8443", {"fake.invalid"}, False),
            ("fake.invalid:8443", {"fake.invalid:8443"}, True),
            ("fake.invalid:0", {"fake.invalid"}, False),
            ("[::1]:8443", {"[::1]:8443"}, True),
            ("user@fake.invalid:443", {"fake.invalid"}, False),
        ):
            handler = object.__new__(_handler(frozenset(allow)))
            handler.path = authority
            handler._connect = Mock(side_effect=OSError)
            handler.send_error = Mock()
            handler._deny = Mock()
            handler.do_CONNECT()
            self.assertEqual(handler._connect.called, permitted, authority)
            self.assertEqual(handler._deny.called, not permitted, authority)

    def test_fake_secret_switch_not_inherited(self):
        with patch.dict(os.environ, {"TOOLSTACK_SPS_FAKE": "1", "PATH": "/bin"}, clear=True):
            self.assertEqual(runner._child_environment(), {"PATH": "/bin"})

    def test_log_directory_symlink_is_refused_without_chmod(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir(mode=0o755)
            before = target.stat().st_mode
            (root / "logs").symlink_to(target, target_is_directory=True)
            with self.assertRaises(OSError):
                runner._tool_log_path(SimpleNamespace(path=root))
            self.assertEqual(target.stat().st_mode, before)
            self.assertFalse((target / "tool.log").exists())

    def test_log_final_component_and_swapped_parent_refuse_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = runner._tool_log_path(SimpleNamespace(path=root))
            target = root / "target"
            target.write_text("unchanged")
            path.symlink_to(target)
            with self.assertRaises(OSError):
                runner._open_tool_log(path)
            path.unlink()
            path.parent.rmdir()
            path.parent.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                runner._open_tool_log(path)
            self.assertEqual(target.read_text(), "unchanged")

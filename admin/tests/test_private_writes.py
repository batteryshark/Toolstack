"""Private admin files are private from creation, independently of umask."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from admin import settings, broker_config


class PrivateWrites(unittest.TestCase):
    def test_config_and_ancestors_private_with_permissive_umask(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"XDG_CONFIG_HOME": root + "/config"}):
            previous = os.umask(0o002)
            try:
                broker_config.save(broker_config.BrokerRunConfig(nod_token="fake-token"))
            finally:
                os.umask(previous)
            path = broker_config.config_file()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(root, "config").stat().st_mode & 0o777, 0o700)

    def test_existing_writable_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root, "unsafe")
            parent.mkdir()
            parent.chmod(0o770)
            with self.assertRaises(PermissionError):
                settings._write_private(parent / "state", "fake")
            self.assertFalse((parent / "state").exists())

    def test_tool_editor_uses_text_nodes_for_option_labels(self):
        from admin.views import assets
        source = Path(assets.__file__).read_text()
        self.assertIn("o.textContent=v", source)
        self.assertNotIn("+'>'+v+'</option>'", source)

    def test_installer_log_directory_is_owner_only(self):
        source = (Path(__file__).resolve().parents[2] / "deploy/install.sh").read_text()
        self.assertIn('-m 700 /var/log/toolstack', source)

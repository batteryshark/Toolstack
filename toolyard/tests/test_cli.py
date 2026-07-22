"""Regression tests for persisted Toolyard lifecycle state."""

import os
import shutil
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from toolyard import cli
from toolyard.runner import RunningTool


class ToolyardCliState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="toolyard-cli-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.previous_state_home = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = str(Path(self.tmp, "state"))
        self.addCleanup(self._restore_state_home)
        self.tools_root = Path(self.tmp, "tools")
        tool_dir = self.tools_root / "echo"
        tool_dir.mkdir(parents=True)
        (tool_dir / "toolyard.toml").write_text(
            'id = "echo"\ntype = "api"\n[entrypoint]\ncommand = "true"\nport = 4601\n',
            encoding="utf-8")

    def _restore_state_home(self):
        if self.previous_state_home is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self.previous_state_home

    def test_up_replaces_dead_record(self):
        stale = RunningTool("echo", 4601, "process", "123")
        cli._save_state({"echo": asdict(stale)})
        replacement = RunningTool("echo", 4601, "process", "456")
        selected_runner = mock.Mock()
        selected_runner.start.return_value = replacement
        recorded_runner = mock.Mock()
        recorded_runner.is_alive.return_value = False
        args = SimpleNamespace(root=str(self.tools_root), id="echo", backend="process")

        with mock.patch.object(cli, "get_runner",
                               side_effect=[selected_runner, recorded_runner]):
            cli.cmd_up(args)

        recorded_runner.stop.assert_called_once_with(stale)
        selected_runner.start.assert_called_once()
        self.assertEqual(cli._load_state()["echo"], asdict(replacement))


if __name__ == "__main__":
    unittest.main()

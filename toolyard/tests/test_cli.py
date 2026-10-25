"""Regression tests for persisted Toolyard lifecycle state."""

import os
import json
import socket
import subprocess
import sys
import shutil
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from toolyard import cli
from toolyard import runner
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

    def test_up_replaces_known_previous_boot_without_pid_operations(self):
        stale = RunningTool("echo", 4601, "process", "123", boot_id="previous",
                            process_identity="old", egress_pid="124", egress_identity="old-helper")
        cli._save_state({"echo": asdict(stale)})
        replacement = RunningTool("echo", 4601, "process", "456")
        selected = mock.Mock()
        selected.start.return_value = replacement
        with mock.patch.object(cli, "get_runner", side_effect=[selected, runner.ProcessRunner()]), mock.patch.object(runner, "_boot_id", return_value="current"), mock.patch.object(runner.os, "kill") as probe, mock.patch.object(runner.os, "killpg") as signal, mock.patch.object(runner.os, "waitpid") as wait:
            cli.cmd_up(SimpleNamespace(root=str(self.tools_root), id="echo", backend="process"))
        probe.assert_not_called()
        signal.assert_not_called()
        wait.assert_not_called()
        self.assertEqual(cli._load_state()["echo"], asdict(replacement))


class CrossInvocationCli(unittest.TestCase):
    def test_up_parent_exits_then_separate_down_confirms_absence(self):
        """Real isolated CLI invocations; the detached child has a finite lifetime."""
        source = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="cli-cross-invocation-") as directory:
            root = Path(directory).resolve()
            tool = root / "tools" / "owned"
            tool.mkdir(parents=True)
            state = root / "state.json"
            receipt = root / "child.json"
            child_script = tool / "child.py"
            child_script.write_text(
                "import os, json, time\nfrom pathlib import Path\n"
                "from toolyard.runner import _process_identity, _boot_id\n"
                f"Path({str(receipt)!r}).write_text(json.dumps({{'pid': os.getpid(), 'start': _process_identity(os.getpid()), 'boot': _boot_id()}}))\n"
                "time.sleep(20)\n", encoding="utf-8")
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            (tool / "toolyard.toml").write_text(
                f'id = "owned"\ntype = "api"\n[entrypoint]\ncommand = "python3 child.py"\nport = {port}\n', encoding="utf-8")
            env = {"PATH": os.environ.get("PATH", ""), "HOME": str(root),
                   "TMPDIR": str(root), "PYTHONPATH": str(source),
                   "TOOLSTACK_SPS_SKIP": "1", "TOOLSTACK_SPS_ENV": str(root / "absent.env"),
                   "TOOLSTACK_TOOLYARD_STATE": str(state),
                   "TOOLSTACK_TOOLYARD_CHANNEL_STATE": str(root / "channels.json")}
            owned = None
            try:
                up = subprocess.run([sys.executable, "-P", "-m", "toolyard.cli", "up", "owned", "--root", str(root / "tools"), "--backend", "process"], env=env, capture_output=True, text=True, timeout=10)
                if receipt.exists():
                    owned = json.loads(receipt.read_text())
                self.assertEqual(up.returncode, 0, up.stderr)
                self.assertIsNotNone(owned)
                record = json.loads(state.read_text())["owned"]
                self.assertEqual(record["handle"], str(owned["pid"]))
                self.assertEqual(record["process_identity"], owned["start"])
                self.assertEqual(record["boot_id"], owned["boot"])
                # The starting CLI has exited; this test is not the child's parent.
                with self.assertRaises(ChildProcessError):
                    os.waitpid(owned["pid"], os.WNOHANG)
                down = subprocess.run([sys.executable, "-P", "-m", "toolyard.cli", "down", "owned"], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(down.returncode, 0, down.stderr)
                self.assertEqual(json.loads(state.read_text()), {})
                self.assertTrue(runner._pid_absent(owned["pid"]))
                print("CROSS_INVOCATION", json.dumps({**owned, "up_exit": up.returncode,
                      "down_exit": down.returncode, "own_reap": False, "positive_esrch": True}), flush=True)
            finally:
                if owned is None and receipt.exists():
                    owned = json.loads(receipt.read_text())
                if owned is not None and not runner._pid_absent(owned["pid"]):
                    runner._terminate(owned["pid"], owned["start"], owned["boot"])


if __name__ == "__main__":
    unittest.main()

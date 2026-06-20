"""admin.toolyard_ops: list tools defined under the tools root with their run
state, and fail cleanly on an unknown tool. Actually starting tools is covered by
toolyard's own runner tests, so this stays light (no process is spawned)."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from admin import toolyard_ops


class ToolyardOps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="admin-ty-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._prev = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = str(Path(self.tmp, "state"))
        self.addCleanup(self._restore)
        self.tools_root = Path(self.tmp, "tools")
        (self.tools_root / "echo").mkdir(parents=True)
        (self.tools_root / "echo" / "toolyard.toml").write_text(
            'id = "echo"\ntype = "api"\n\n[entrypoint]\ncommand = "python3 app.py"\nport = 4601\n',
            encoding="utf-8",
        )

    def _restore(self):
        if self._prev is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self._prev

    def test_list_tools_reports_defined_not_running(self):
        tools = toolyard_ops.list_tools(str(self.tools_root))
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["id"], "echo")
        self.assertEqual(tools[0]["path"], str(self.tools_root / "echo"))
        self.assertFalse(tools[0]["running"])
        self.assertFalse(tools[0]["alive"])

    def test_list_tools_includes_explicit_tool_dirs(self):
        other = Path(self.tmp, "elsewhere", "weather")
        other.mkdir(parents=True)
        (other / "toolyard.toml").write_text(
            'id = "weather"\ntype = "api"\n[entrypoint]\ncommand = "python3 app.py"\nport = 4700\n',
            encoding="utf-8")
        ids = {t["id"] for t in toolyard_ops.list_tools(str(self.tools_root), [str(other)])}
        self.assertEqual(ids, {"echo", "weather"})

    def test_removable_flag_marks_only_tool_dirs(self):
        other = Path(self.tmp, "elsewhere", "weather")
        other.mkdir(parents=True)
        (other / "toolyard.toml").write_text(
            'id = "weather"\ntype = "api"\n[entrypoint]\ncommand = "x"\nport = 4700\n', encoding="utf-8")
        tools = {t["id"]: t for t in toolyard_ops.list_tools(str(self.tools_root), [str(other)])}
        self.assertFalse(tools["echo"]["removable"])     # discovered under the tools root
        self.assertTrue(tools["weather"]["removable"])   # registered as an explicit tool dir

    def test_stop_unknown_tool_is_noop(self):
        toolyard_ops.stop("ghost")  # no state, no error

    def test_start_unknown_tool_raises(self):
        with self.assertRaises(LookupError):
            toolyard_ops.start("ghost", str(self.tools_root), [], "secrets.toml")

    def test_remove_deletes_a_managed_tool_dir(self):
        self.assertTrue((self.tools_root / "echo").exists())
        toolyard_ops.remove("echo", str(self.tools_root))
        self.assertFalse((self.tools_root / "echo").exists())   # folder gone
        self.assertEqual(toolyard_ops.list_tools(str(self.tools_root)), [])

    def test_remove_unknown_tool_raises(self):
        with self.assertRaises(LookupError):
            toolyard_ops.remove("ghost", str(self.tools_root))

    def test_remove_refuses_external_tool_dir(self):
        # A tool registered from an external dir is the operator's folder — never delete it.
        other = Path(self.tmp, "elsewhere", "weather")
        other.mkdir(parents=True)
        (other / "toolyard.toml").write_text(
            'id = "weather"\ntype = "api"\n[entrypoint]\ncommand = "x"\nport = 4700\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            toolyard_ops.remove("weather", str(self.tools_root), [str(other)])
        self.assertTrue(other.exists())   # left on disk


if __name__ == "__main__":
    unittest.main()

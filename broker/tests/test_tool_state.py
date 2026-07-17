"""ToolState: broker-side reader for the toolyard state file (Phase 4)."""
import json
import os
import time
import unittest
from pathlib import Path

from broker.tool_state import ToolState


class _State:
    def __init__(self, d: dict, mtime: float = 0.0):
        self.d = d
        self.mtime = mtime


def _write(state_path: Path, payload: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(payload))


class Lookup(unittest.TestCase):
    def test_e_secret_for_known(self):
        d = Path(tempfile := __import__("tempfile").mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        sp = d / "state.json"
        _write(sp, {"echo": {"e_secret": "es-1", "tool_id": "echo"},
                    "echo-mcp": {"e_secret": "es-2", "tool_id": "echo-mcp"}})
        ts = ToolState(path=sp)
        self.assertEqual(ts.e_secret_for("echo"), "es-1")
        self.assertEqual(ts.e_secret_for("echo-mcp"), "es-2")
        self.assertIsNone(ts.e_secret_for("none"))

    def test_unknown_tool_returns_none(self):
        d = Path(tempfile := __import__("tempfile").mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        sp = d / "state.json"
        _write(sp, {})
        ts = ToolState(path=sp)
        self.assertIsNone(ts.e_secret_for("anything"))

    def test_missing_file_is_silent(self):
        d = Path(tempfile := __import__("tempfile").mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        ts = ToolState(path=d / "nope.json")
        self.assertIsNone(ts.e_secret_for("echo"))

    def test_mtime_invalidation(self):
        d = Path(tempfile := __import__("tempfile").mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        sp = d / "state.json"
        _write(sp, {"echo": {"e_secret": "es-1"}})
        ts = ToolState(path=sp)
        self.assertEqual(ts.e_secret_for("echo"), "es-1")

        # mtime advance + new value -> tool_state reruns and reads the new value.
        time.sleep(0.05)
        _write(sp, {"echo": {"e_secret": "es-2"}})
        self.assertEqual(ts.e_secret_for("echo"), "es-2")

    def test_record_without_e_secret_skipped(self):
        d = Path(tempfile := __import__("tempfile").mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        sp = d / "state.json"
        _write(sp, {"echo": {"tool_id": "echo"},  # no e_secret
                    "alive": {"e_secret": "es-2"}})
        ts = ToolState(path=sp)
        self.assertIsNone(ts.e_secret_for("echo"))
        self.assertEqual(ts.e_secret_for("alive"), "es-2")

    def test_tool_ids_lists_registered(self):
        d = Path(tempfile := __import__("tempfile").mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, ignore_errors=True)
        sp = d / "state.json"
        _write(sp, {"echo": {"e_secret": "es-1"},
                    "echo-mcp": {"e_secret": "es-2"}})
        ts = ToolState(path=sp)
        self.assertEqual(sorted(ts.tool_ids()), ["echo", "echo-mcp"])

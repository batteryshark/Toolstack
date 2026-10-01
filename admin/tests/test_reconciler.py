"""Reconciler: restart dead state.json tools after SPS is up."""
import os
import tempfile
import unittest
from dataclasses import asdict
from unittest import mock

from admin import reconciler
from toolyard.cli import _load_state, _save_state
from toolyard.runner import RunningTool


class _Cfg:
    tools_root = "/tools"
    tool_dirs = []


def _record(tool_id="echo", backend="process", handle="123"):
    return asdict(RunningTool(tool_id, 4601, backend, handle, boot_id="boot"))


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="reconcile-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, ignore_errors=True)
        self._prev = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = self.tmp
        self.addCleanup(self._restore)

    def _restore(self):
        if self._prev is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self._prev

    def test_waits_for_sps_then_starts_dead_tools(self):
        _save_state({"echo": _record()})
        link = mock.Mock()
        link.wait_until_up.return_value = True
        with mock.patch("admin.reconciler.toolyard_ops.start") as start, \
             mock.patch("admin.reconciler.get_runner") as get_runner:
            get_runner.return_value.is_alive.return_value = False
            n = reconciler.reconcile_running_tools(_Cfg(), link, wait_timeout=1.0)
        self.assertEqual(n, 1)
        start.assert_called_once_with("echo", "/tools", [], backend="process")

    def test_skips_alive_tools(self):
        _save_state({"echo": _record()})
        link = mock.Mock()
        link.wait_until_up.return_value = True
        with mock.patch("admin.reconciler.toolyard_ops.start") as start, \
             mock.patch("admin.reconciler.get_runner") as get_runner:
            get_runner.return_value.is_alive.return_value = True
            n = reconciler.reconcile_running_tools(_Cfg(), link, wait_timeout=1.0)
        self.assertEqual(n, 0)
        start.assert_not_called()

    def test_no_start_when_sps_not_up(self):
        _save_state({"echo": _record()})
        link = mock.Mock()
        link.wait_until_up.return_value = False
        with mock.patch("admin.reconciler.toolyard_ops.start") as start:
            n = reconciler.reconcile_running_tools(_Cfg(), link, wait_timeout=1.0)
        self.assertEqual(n, 0)
        start.assert_not_called()

    def test_unknown_tool_is_logged_not_raised(self):
        _save_state({"ghost": _record("ghost")})
        link = mock.Mock()
        link.wait_until_up.return_value = True
        with mock.patch("admin.reconciler.toolyard_ops.start",
                        side_effect=LookupError("unknown tool")), \
             mock.patch("admin.reconciler.get_runner") as get_runner:
            get_runner.return_value.is_alive.return_value = False
            n = reconciler.reconcile_running_tools(_Cfg(), link, wait_timeout=1.0)
        self.assertEqual(n, 0)

    def test_none_link_starts_dead_tools(self):
        _save_state({"echo": _record()})
        with mock.patch("admin.reconciler.toolyard_ops.start") as start, \
             mock.patch("admin.reconciler.get_runner") as get_runner:
            get_runner.return_value.is_alive.return_value = False
            n = reconciler.reconcile_running_tools(_Cfg(), None, wait_timeout=1.0)
        self.assertEqual(n, 1)
        start.assert_called_once_with("echo", "/tools", [], backend="process")

    def test_gate_exception_is_contained(self):
        _save_state({"echo": _record()})
        link = mock.Mock()
        link.wait_until_up.side_effect = RuntimeError("boom")
        n = reconciler.reconcile_running_tools(_Cfg(), link, wait_timeout=1.0)
        self.assertEqual(n, 0)

    def test_restart_failure_preserves_record(self):
        _save_state({"echo": _record()})
        link = mock.Mock()
        link.wait_until_up.return_value = True

        def fake_start(tool_id, *a, **k):
            s = _load_state()
            s.pop(tool_id, None)
            _save_state(s)
            raise RuntimeError("boom")

        with mock.patch("admin.reconciler.toolyard_ops.start",
                        side_effect=fake_start), \
             mock.patch("admin.reconciler.get_runner") as get_runner:
            get_runner.return_value.is_alive.return_value = False
            n = reconciler.reconcile_running_tools(_Cfg(), link, wait_timeout=1.0)
        self.assertEqual(n, 0)
        self.assertIn("echo", _load_state())


if __name__ == "__main__":
    unittest.main()

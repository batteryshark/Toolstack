"""Tests for the SPS restart watchdog (admin/sps_watchdog.py)."""
from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from admin.sps_watchdog import SPSWatchdog


def _dummy_config(tools_root: str = "tools", tool_dirs=()):
    cfg = mock.Mock()
    cfg.tools_root = tools_root
    cfg.tool_dirs = list(tool_dirs)
    return cfg


class SPSWatchdogTests(unittest.TestCase):

    def setUp(self) -> None:
        self.cfg = _dummy_config()
        self.probe_value = {"id": None}
        self.re_registered = []
        self.re_register_lock = threading.Lock()
        self.cfg_ev = threading.Event()

        def re_register(**kwargs):
            with self.re_register_lock:
                self.re_registered.append(kwargs)
            self.cfg_ev.set()
            return 2  # pretend we re-registered 2 tools

        self.re_register = re_register
        self.wd = SPSWatchdog(
            config=self.cfg,
            probe=lambda: self.probe_value["id"],
            re_register_fn=re_register,
            sps_env_path="/etc/toolstack/sps.env",
            poll_interval=0.01,
        )

    @staticmethod
    def _boom():
        raise OSError("refused")

    def test_probe_returns_none_is_noop(self) -> None:
        """When SPS hasn't reported a boot_id yet (or is down), the watchdog
        must not attempt re-registration."""
        self.wd._check_once()
        self.assertEqual(self.re_registered, [])

    def test_empty_probe_value_is_treated_as_not_up(self) -> None:
        """An empty-string boot_id (SPS up but not yet reporting an id) must be
        treated the same as None: no re-registration."""
        self.probe_value["id"] = ""
        self.wd._check_once()
        self.assertEqual(self.re_registered, [])

    def test_probe_error_is_swallowed(self) -> None:
        wd = SPSWatchdog(
            config=self.cfg,
            probe=self._boom,
            re_register_fn=self.re_register,
            sps_env_path="/etc/toolstack/sps.env",
            poll_interval=0.01,
        )
        wd._check_once()  # must not raise
        self.assertEqual(self.re_registered, [])

    def test_first_seen_boot_id_triggers_re_register(self) -> None:
        self.probe_value["id"] = "first-id"
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 1)
        # The re_register call got the right config-derived kwargs.
        kw = self.re_registered[0]
        self.assertEqual(kw["tools_root"], "tools")
        self.assertEqual(kw["sps_env_path"], "/etc/toolstack/sps.env")

    def test_same_boot_id_is_noop(self) -> None:
        self.probe_value["id"] = "stable-id"
        self.wd._check_once()
        self.wd._check_once()
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 1)

    def test_new_boot_id_triggers_another_re_register(self) -> None:
        self.probe_value["id"] = "first-id"
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 1)

        self.probe_value["id"] = "second-id"
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 2)

        self.probe_value["id"] = "third-id"
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 3)

    def test_thread_loop_detects_changes(self) -> None:
        """End-to-end: spin the watchdog's loop, change the probed boot_id,
        watch re_register fire."""
        self.wd._interval = 0.02
        self.wd.start()
        try:
            self.probe_value["id"] = "alpha"
            self.assertTrue(self.cfg_ev.wait(2.0), "watchdog did not fire on first id")
            self.cfg_ev.clear()

            self.probe_value["id"] = "beta"
            self.assertTrue(self.cfg_ev.wait(2.0), "watchdog did not fire on second id")
        finally:
            self.wd.stop()
            self.wd.join(timeout=2.0)

        self.assertGreaterEqual(len(self.re_registered), 2)

    def test_re_register_failure_does_not_kill_loop(self) -> None:
        """A re_register exception must be caught and logged; the loop keeps
        running."""
        call_count = [0]
        def failing(**kwargs):
            call_count[0] += 1
            raise RuntimeError("sps unreachable")

        wd = SPSWatchdog(
            config=self.cfg,
            probe=lambda: self.probe_value["id"],
            re_register_fn=failing,
            sps_env_path="/etc/toolstack/sps.env",
            poll_interval=0.01,
        )
        wd.start()
        try:
            self.probe_value["id"] = "first"
            time.sleep(0.1)
            self.probe_value["id"] = "second"
            time.sleep(0.1)
        finally:
            wd.stop()
            wd.join(timeout=2.0)
        # The exception was swallowed and the loop kept processing changes.
        self.assertGreaterEqual(call_count[0], 2)

    def test_re_register_runs_under_the_lock(self) -> None:
        """When a lock is provided, the re-register pass must run while it is
        held (so it can share ``reconciler.RECONCILE_LOCK``)."""
        lock = threading.Lock()
        held = []

        def re_register(**kwargs):
            held.append(lock.locked())
            return 1

        wd = SPSWatchdog(
            config=self.cfg,
            probe=lambda: self.probe_value["id"],
            re_register_fn=re_register,
            sps_env_path="/etc/toolstack/sps.env",
            poll_interval=0.01,
            lock=lock,
        )
        self.probe_value["id"] = "under-lock"
        wd._check_once()
        self.assertEqual(held, [True])
        self.assertFalse(lock.locked())  # released after the pass


if __name__ == "__main__":
    unittest.main()

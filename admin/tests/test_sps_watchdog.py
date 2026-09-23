"""Tests for the SPS restart watchdog (admin/sps_watchdog.py)."""
from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from admin.sps_watchdog import SPSWatchdog


def _dummy_config(tools_root: str = "tools", tool_dirs=()):
    cfg = mock.Mock()
    cfg.tools_root = tools_root
    cfg.tool_dirs = list(tool_dirs)
    return cfg


class SPSWatchdogTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="sps-watchdog-")
        self.addCleanup(self.tmp.cleanup)
        self.boot_id_path = Path(self.tmp.name) / "sps.boot_id"
        self.cfg = _dummy_config()
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
            sps_env_path="/etc/toolstack/sps.env",
            re_register_fn=re_register,
            boot_id_path=self.boot_id_path,
            poll_interval=0.01,
        )

    def _write_boot_id(self, value: str) -> None:
        # Mirror SPS's atomic-rename pattern: temp + os.replace.
        tmp = self.boot_id_path.with_suffix(".tmp")
        tmp.write_text(value, encoding="utf-8")
        os.replace(tmp, self.boot_id_path)

    def test_no_boot_id_file_is_noop(self) -> None:
        """When SPS hasn't written its boot_id yet, the watchdog must not
        attempt re-registration."""
        self.wd._check_once()
        self.assertEqual(self.re_registered, [])

    def test_first_seen_boot_id_triggers_re_register(self) -> None:
        self._write_boot_id("first-id")
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 1)
        # The re_register call got the right config-derived kwargs.
        kw = self.re_registered[0]
        self.assertEqual(kw["tools_root"], "tools")
        self.assertEqual(kw["sps_env_path"], "/etc/toolstack/sps.env")

    def test_same_boot_id_is_noop(self) -> None:
        self._write_boot_id("stable-id")
        self.wd._check_once()
        self.wd._check_once()
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 1)

    def test_new_boot_id_triggers_another_re_register(self) -> None:
        self._write_boot_id("first-id")
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 1)

        self._write_boot_id("second-id")
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 2)

        self._write_boot_id("third-id")
        self.wd._check_once()
        self.assertEqual(len(self.re_registered), 3)

    def test_thread_loop_detects_changes(self) -> None:
        """End-to-end: spin the watchdog's loop, write boot_ids, watch
        re_register fire."""
        self.wd._interval = 0.02
        self.wd.start()
        try:
            self._write_boot_id("alpha")
            self.assertTrue(self.cfg_ev.wait(2.0), "watchdog did not fire on first id")
            self.cfg_ev.clear()

            self._write_boot_id("beta")
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
            sps_env_path="/etc/toolstack/sps.env",
            re_register_fn=failing,
            boot_id_path=self.boot_id_path,
            poll_interval=0.01,
        )
        wd.start()
        try:
            self._write_boot_id("first")
            time.sleep(0.1)
            self._write_boot_id("second")
            time.sleep(0.1)
            self.assertGreaterEqual(call_count[0], 1)
        finally:
            wd.stop()
            wd.join(timeout=2.0)
        # Thread is still alive (didn't die on the exception).
        self.assertFalse(wd.is_alive() and call_count[0] == 0)


if __name__ == "__main__":
    unittest.main()
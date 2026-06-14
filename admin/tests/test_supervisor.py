"""admin.supervisor: spawn a real broker, confirm it becomes healthy, then stop
it — exercising the posix_spawn/killpg/health-probe lifecycle and the state file.

Runs on stdlib Python (no FastAPI needed). Must be run from the repo root so the
spawned ``python -m broker.server`` can import the broker package.
"""

import os
import shutil
import socket
import tempfile
import unittest
from pathlib import Path

from admin import settings, supervisor
from admin.broker_config import BrokerRunConfig


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Supervisor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="admin-sup-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._prev_xdg = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = str(Path(self.tmp, "state"))
        self.addCleanup(self._restore_xdg)
        self.addCleanup(supervisor.stop)  # kill the broker even if an assert fails

        tools_root = Path(self.tmp, "tools")
        tools_root.mkdir(parents=True, exist_ok=True)  # empty registry; health still OK
        self.config = BrokerRunConfig(
            port=_free_port(),
            db_path=str(Path(self.tmp, "broker.sqlite3")),
            tools_root=str(tools_root),
        )

    def _restore_xdg(self):
        if self._prev_xdg is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self._prev_xdg

    def test_status_is_stopped_before_start(self):
        self.assertEqual(supervisor.status()["running"], False)

    def test_start_becomes_healthy_then_stop(self):
        started = supervisor.start(self.config)
        self.assertTrue(started["running"])
        self.assertTrue(started["healthy"], f"broker not healthy; log:\n{supervisor.log_tail()}")
        self.assertEqual(started["port"], self.config.port)
        self.assertTrue(settings.state_dir().joinpath("broker.state.json").exists())

        # a second start is idempotent (returns the running broker, no second spawn)
        again = supervisor.start(self.config)
        self.assertEqual(again["pid"], started["pid"])

        supervisor.stop()
        self.assertEqual(supervisor.status()["running"], False)
        self.assertFalse(settings.state_dir().joinpath("broker.state.json").exists())

    def test_restart_replaces_process(self):
        first = supervisor.start(self.config)
        second = supervisor.restart(self.config)
        self.assertTrue(second["healthy"], f"broker not healthy; log:\n{supervisor.log_tail()}")
        self.assertNotEqual(first["pid"], second["pid"])


if __name__ == "__main__":
    unittest.main()

"""SPS-restart watchdog.

SPS's tool-registration pool is intentionally in-memory only (see
``sps/store.py``): every restart wipes every tool's registration, and
the runner is supposed to re-register on every tool start. But tools that
were already running when SPS restarted never know -- their SPS calls start
returning "Not found" until they're manually bounced.

This watchdog closes that gap. SPS writes a fresh random ``boot_id`` to a
known file at startup (``/var/lib/toolstack/sps.boot_id``). This thread polls
that file; whenever the id changes, it walks every running tool in the
toolyard state and re-registers it via the existing
``toolyard.runner.reregister_all_with_sps`` (idempotent: overwrites the
existing registration).

The watchdog lives in admin because admin is the long-lived supervisor.
The broker process is short-lived (supervised by ``admin.supervisor``) and
recreated by systemd on its own schedule, so it cannot host a persistent
watcher. The forwarders themselves cannot host it either -- they don't have
the ``SP_SECRET`` that ``handle_register`` requires.
"""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .broker_config import BrokerRunConfig


log = logging.getLogger(__name__)


# Where SPS writes its boot identity. Matches sps/cli.py:_DEFAULT_BOOT_ID_PATH.
_DEFAULT_BOOT_ID_PATH = (
    Path(os.environ.get("XDG_STATE_HOME") or "/var/lib")
    / "toolstack"
    / "sps.boot_id"
)

DEFAULT_POLL_INTERVAL = 30.0  # seconds


class SPSWatchdog(threading.Thread):
    """Poll SPS's boot_id file; on change, re-register every running tool."""

    daemon = True  # don't block process exit

    def __init__(
        self,
        *,
        config: "BrokerRunConfig",
        sps_env_path: str,
        re_register_fn,
        boot_id_path: Path | None = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        super().__init__(name="sps-watchdog")
        self._config = config
        self._sps_env_path = sps_env_path
        self._re_register = re_register_fn
        self._path = Path(boot_id_path) if boot_id_path else _DEFAULT_BOOT_ID_PATH
        self._interval = float(poll_interval)
        self._last_seen: str | None = None
        # NOTE: do not name this ``_stop`` -- ``threading.Thread`` already uses
        # that name internally (Thread._stop is called by Thread.join).
        self._stop_event = threading.Event()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop to exit; safe to call multiple times."""
        self._stop_event.set()

    def run(self) -> None:  # pragma: no cover (loop; tested via _check_once)
        log.info(
            "SPS watchdog watching %s every %.0fs",
            self._path, self._interval,
        )
        while not self._stop_event.is_set():
            try:
                self._check_once()
            except Exception:
                # Never let a transient error kill the loop.
                log.exception("SPS watchdog tick failed")
            self._stop_event.wait(self._interval)

    def _check_once(self) -> None:
        cur = self._read_boot_id()
        if cur is None:
            return  # SPS not (yet) started, or file unreadable
        if cur == self._last_seen:
            return
        log.info(
            "SPS boot_id changed: %r -> %r (re-registering tools)",
            self._last_seen, cur,
        )
        self._last_seen = cur
        self._re_register_all()

    def _read_boot_id(self) -> str | None:
        try:
            content = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            log.warning("SPS watchdog: cannot read %s: %s", self._path, exc)
            return None
        content = content.strip()
        return content or None

    def _re_register_all(self) -> None:
        try:
            count = self._re_register(
                tools_root=self._config.tools_root,
                tool_dirs=self._config.tool_dirs,
                sps_env_path=self._sps_env_path,
            )
            log.info("SPS watchdog re-registered %d tool(s)", count)
        except Exception:
            log.exception("SPS re-registration pass failed")
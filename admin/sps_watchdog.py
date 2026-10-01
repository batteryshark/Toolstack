"""SPS-restart watchdog.

SPS's tool-registration pool is intentionally in-memory only (see
``sps/store.py``): every restart wipes every tool's registration, and
the runner is supposed to re-register on every tool start. But tools that
were already running when SPS restarted never know -- their SPS calls start
returning "Not found" until they're manually bounced.

This watchdog closes that gap. SPS answers a secret-free ``ping`` with its
random ``boot_id``. This thread polls an injected ``probe`` callable (the live
``SPSLink.boot_id``); whenever the id changes, it walks every running tool in
the toolyard state and re-registers it via the existing
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
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .broker_config import BrokerRunConfig


log = logging.getLogger(__name__)


DEFAULT_POLL_INTERVAL = 30.0  # seconds


class SPSWatchdog(threading.Thread):
    """Poll SPS's live boot_id; on change, re-register every running tool."""

    daemon = True  # don't block process exit

    def __init__(
        self,
        *,
        config: "BrokerRunConfig",
        probe,
        re_register_fn,
        sps_env_path: str,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        lock=None,
    ) -> None:
        super().__init__(name="sps-watchdog")
        self._config = config
        self._probe = probe
        self._re_register = re_register_fn
        self._sps_env_path = sps_env_path
        self._interval = float(poll_interval)
        self._lock = lock
        self._last_seen: str | None = None
        # NOTE: do not name this ``_stop`` -- ``threading.Thread`` already uses
        # that name internally (Thread._stop is called by Thread.join).
        self._stop_event = threading.Event()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop to exit; safe to call multiple times."""
        self._stop_event.set()

    def run(self) -> None:  # pragma: no cover (loop; tested via _check_once)
        log.info("SPS watchdog polling every %.0fs", self._interval)
        while not self._stop_event.is_set():
            try:
                self._check_once()
            except Exception:
                # Never let a transient error kill the loop.
                log.exception("SPS watchdog tick failed")
            self._stop_event.wait(self._interval)

    def _check_once(self) -> None:
        try:
            cur = self._probe()
        except Exception as exc:
            # SPS not up yet, or a transient error: try again next tick.
            log.debug("SPS watchdog probe failed: %s", exc)
            return
        if not cur or cur == self._last_seen:
            return
        log.info(
            "SPS boot_id changed: %r -> %r (re-registering tools)",
            self._last_seen, cur,
        )
        self._last_seen = cur
        self._re_register_all()

    def _re_register_all(self) -> None:
        def _pass() -> int:
            return self._re_register(
                tools_root=self._config.tools_root,
                tool_dirs=self._config.tool_dirs,
                sps_env_path=self._sps_env_path,
            )

        # The pass is short for the process backend and holding the lock across
        # it serializes re-registration against reconcile-driven tool starts.
        try:
            if self._lock is not None:
                with self._lock:
                    count = _pass()
            else:
                count = _pass()
            log.info("SPS watchdog re-registered %d tool(s)", count)
        except Exception:
            log.exception("SPS re-registration pass failed")

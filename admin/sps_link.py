"""One live link to SPS for readiness gating and restart detection.

The admin owns SPS re-registration (it holds SP_SECRET; a tool holds only its
per-tool E_SECRET and cannot re-register itself). This module exposes a single
primitive -- a ping round trip returning SPS's random per-process boot_id --
used for two things:

  * readiness: wait until SPS answers before starting tool forwarders, so a
    forwarder is never launched secretless during an SPS restart;
  * restart detection: a changed boot_id means SPS lost its in-memory tool
    pool, so already-running tools must be re-registered.

A random boot_id (not a PID) is the change token: PIDs recycle, so a PID match
could hide a restart.
"""
from __future__ import annotations

import logging
import os
import time

from sps.client import SPSError, SPSClient
from sps.config import load_config

log = logging.getLogger(__name__)

_DEFAULT_SPS_ENV = "/etc/toolstack/sps.env"


class SPSLink:
    def __init__(self, host: str, port: int, ca_file: str | None,
                 verify: bool = True) -> None:
        self.host = host
        self.port = int(port)
        self.ca_file = ca_file
        self.verify = verify

    @classmethod
    def from_env(cls, sps_env_path: str | None = None) -> "SPSLink | None":
        """Build a link from the SPS env file, or None when SPS is not configured
        (dev / no-secrets mode). Mirrors runner.start()'s sps_active check."""
        if os.environ.get("TOOLSTACK_SPS_SKIP") == "1":
            return None
        # TOOLSTACK_SPS_ENV override is deliberate: mirrors toolyard/runner.py
        # and admin/server.py so all components resolve the same env file.
        path = sps_env_path or os.environ.get("TOOLSTACK_SPS_ENV", _DEFAULT_SPS_ENV)
        if not os.path.exists(path):
            return None
        try:
            cfg = load_config(path)
            # Resolve env overrides inside the guard: a bad value (e.g.
            # TOOLSTACK_SPS_PORT=abc) must not raise into startup.
            verify = os.environ.get("TOOLSTACK_SPS_VERIFY", "1") == "1"
            return cls(
                host=os.environ.get("TOOLSTACK_SPS_HOST", cfg.sp_host),
                port=int(os.environ.get("TOOLSTACK_SPS_PORT", str(cfg.sp_port))),
                ca_file=os.environ.get("TOOLSTACK_SPS_CA", cfg.sp_tls_ca),
                verify=verify,
            )
        except Exception as exc:
            log.warning("SPS link: cannot load %s: %s", path, exc)
            return None

    def boot_id(self, timeout: float | None = None) -> str:
        """Ping SPS and return its current boot_id. Raises on any failure."""
        cli = SPSClient(self.host, self.port, ca_file=self.ca_file,
                        verify=self.verify, timeout=timeout or 15.0)
        boot_id = str(cli.ping().get("boot_id") or "")
        if not boot_id:
            raise SPSError("SPS ping returned no boot_id")
        return boot_id

    def wait_until_up(self, timeout: float, interval: float = 0.5) -> bool:
        """Poll boot_id() until it succeeds or the deadline passes."""
        deadline = time.monotonic() + timeout
        interval = max(interval, 0.05)
        while True:
            remaining = deadline - time.monotonic()
            try:
                self.boot_id(timeout=max(0.1, min(15.0, remaining)))
                return True
            except (OSError, SPSError) as exc:  # a real bug (e.g. TypeError) propagates
                if time.monotonic() >= deadline:
                    log.warning("SPS not reachable after %.0fs: %s", timeout, exc)
                    return False
                time.sleep(min(interval, max(0.0, remaining)))

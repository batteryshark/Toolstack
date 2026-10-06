"""Restart tool forwarders that state.json says should be running but aren't.

Forwarders are posix_spawn children of the admin process and live in its
systemd cgroup, so any admin restart (e.g. needrestart after an openssl
upgrade) SIGTERMs them all. state.json records running *intent*; this module
reconciles reality to that intent on admin startup.

SPS gate: a forwarder needs SPS at boot (the runner registers it and the tool
pulls its secrets). When the registration call fails, runner.start() now fails
closed for a tool that declares secrets (it raises rather than launching
secretless); only tools with no declared secrets degrade to a secretless run.
So wait for SPS to answer before starting anything.
"""
from __future__ import annotations

import logging
import threading

from toolyard.cli import _load_state, _save_state
from toolyard.runner import RunningTool, get_runner

from . import toolyard_ops

log = logging.getLogger(__name__)

# Serialises reconcile against the SPS watchdog's re-registration pass; both
# act on the same state.json records.
RECONCILE_LOCK = threading.Lock()


def reconcile_running_tools(config, link, *, wait_timeout: float = 60.0) -> int:
    """Restart every dead tool recorded in state.json. Returns the count started.

    No-op (0) when SPS is configured but not reachable within wait_timeout:
    starting a forwarder then launches it without secrets, which is worse than
    leaving it down for an operator (or a later retry) to fix."""
    try:
        if link is not None and not link.wait_until_up(wait_timeout):
            log.error("reconcile: SPS not up after %.0fs; not starting tools", wait_timeout)
            return 0

        state = _load_state()
        started = 0
        for tool_id, rec in state.items():
            if not isinstance(rec, dict):
                continue
            # Hold the lock per tool, not for the whole pass: a Docker start can take
            # up to 600s, and holding it across the loop would starve the watchdog.
            with RECONCILE_LOCK:
                try:
                    running = RunningTool(**rec)
                    alive = get_runner(running.backend).is_alive(running)
                except Exception:
                    log.exception("reconcile: cannot assess %s; skipping", tool_id)
                    continue
                if alive:
                    continue
                try:
                    toolyard_ops.start(tool_id, config.tools_root, config.tool_dirs,
                                       backend=running.backend)
                    started += 1
                    log.info("reconcile: restarted %s", tool_id)
                except LookupError:
                    log.warning("reconcile: %s in state but not discoverable; leaving record", tool_id)
                except (Exception, SystemExit):
                    # start() deletes and persists the record before launching; if the
                    # launch then fails, restore intent so the tool isn't down and unrecorded.
                    # Re-read + merge rather than writing our stale snapshot, which would
                    # revert tools that were successfully restarted earlier in this pass.
                    log.exception("reconcile: failed to restart %s; restoring intent", tool_id)
                    current = _load_state()
                    current.setdefault(tool_id, rec)  # keep any newer record; restore intent if gone
                    _save_state(current)
        return started
    except Exception:
        log.exception("reconcile pass failed")
        return 0


def start_reconciler_thread(config, link, *, wait_timeout: float = 60.0) -> threading.Thread:
    t = threading.Thread(
        target=reconcile_running_tools, args=(config, link),
        kwargs={"wait_timeout": wait_timeout}, name="tool-reconciler", daemon=True)
    t.start()
    return t

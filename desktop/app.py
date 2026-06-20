"""Toolstack desktop: a thin native window around the admin control panel.

It reuses everything; it does not reimplement the admin, it *launches* it. If the admin
isn't already serving, it starts ``python -m admin serve`` (which supervises the broker and
runs tools), waits for it to be healthy, and opens a native OS-WebKit window onto it via
pywebview, the operating system's own webview, not a bundled browser. Close the window and
the admin THIS app started is stopped; an admin you already had running is left untouched.

The lifecycle (health / start / stop) is stdlib and unit-tested. pywebview is imported
LAZILY (only when actually opening the window), so this module imports (and its tests run)
without the GUI dependency installed.

Run:   python3 -m desktop
Setup: a venv with the stack + admin deps + pywebview (see desktop/README.md); set the admin
       password once with  python3 -m admin set-password.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8780"
WINDOW_TITLE = "Toolstack"


def _admin_url() -> str:
    """The admin URL the window opens (and the port it starts the admin on if needed).
    ``TOOLSTACK_ADMIN_URL`` overrides the loopback default."""
    return os.environ.get("TOOLSTACK_ADMIN_URL") or DEFAULT_URL


def _port_of(url: str) -> str:
    """The port in an ``http://host:port[/...]`` URL, or 8780 if absent. Strips the path
    first, so a colon in a path/query can't be mistaken for the port."""
    authority = url.split("://", 1)[-1].split("/", 1)[0]  # host[:port], no path/query
    tail = authority.rsplit(":", 1)[-1]
    return tail if tail.isdigit() else "8780"


def admin_healthy(url: str = DEFAULT_URL, timeout: float = 1.0) -> bool:
    """True if the admin is serving. ``GET /login`` is its cheap, unauthenticated liveness
    page (the admin has no token-free health route; /login returns 200 without a session)."""
    try:
        with urllib.request.urlopen(f"{url}/login", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


class Stack:
    """Ensures the admin is up for the window. Owns the admin process ONLY if it started it,
    so closing the window never kills an admin you were already running."""

    def __init__(self, url: str = DEFAULT_URL, serve_cmd: list[str] | None = None) -> None:
        self.url = url
        self._serve_cmd = serve_cmd or [sys.executable, "-m", "admin", "serve",
                                        "--port", _port_of(url)]
        self._proc: subprocess.Popen | None = None

    def started_admin(self) -> bool:
        """Whether THIS app started the admin (vs. found one already running)."""
        return self._proc is not None

    def ensure_up(self, tries: int = 120, delay: float = 0.25) -> None:
        """No-op if the admin is already serving; otherwise start it and wait for health.
        Raises RuntimeError if it exits early (most often no password set, where the admin fails
        closed) or never becomes healthy.

        The admin inherits our stdout/stderr (its logs go to the console, like the broker
        supervisor's log); deliberately NOT a pipe, which would fill and block a long-running
        admin we never drain. So on early exit we point at running it directly to see why."""
        if admin_healthy(self.url):
            return
        self._proc = subprocess.Popen(self._serve_cmd)
        for _ in range(tries):
            if self._proc.poll() is not None:  # exited before it served
                self._proc = None
                raise RuntimeError(
                    "the admin exited before it became healthy. Run `python3 -m admin serve` "
                    "to see why; most often no password is set yet "
                    "(`python3 -m admin set-password`)."
                )
            if admin_healthy(self.url):
                return
            time.sleep(delay)
        self.stop()
        raise RuntimeError(f"the admin did not become healthy at {self.url} in time")

    def stop(self) -> None:
        """Stop the admin we started (idempotent; leaves an externally-run admin alone)."""
        proc, self._proc = self._proc, None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)  # reap it, don't leave a zombie


def main() -> None:
    stack = Stack(_admin_url())
    try:
        stack.ensure_up()
    except RuntimeError as exc:
        # A double-clicked app has no terminal, but still print for the CLI case. The usual
        # cause is "no admin password set"; that message says exactly what to run.
        print(f"toolstack-desktop: {exc}", file=sys.stderr)
        raise SystemExit(1)
    try:
        import webview  # lazy: the one place the GUI dependency is needed
    except ModuleNotFoundError:
        stack.stop()
        raise SystemExit("desktop shell needs pywebview: pip install -r desktop/requirements.txt")
    # create_window is inside the finally too: if opening the window fails (e.g. no GUI
    # session), still stop the admin we started rather than orphaning it.
    try:
        webview.create_window(WINDOW_TITLE, stack.url, width=1180, height=820)
        webview.start()  # blocks until the window is closed
    finally:
        stack.stop()  # stop the admin we started; an already-running one is untouched


if __name__ == "__main__":
    main()

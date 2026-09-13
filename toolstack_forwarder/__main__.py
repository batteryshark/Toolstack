"""Entrypoint for ``python3 -m toolstack_forwarder``.

Reads secrets from SPS (via sps.tool_sdk.SecretClient) instead of the
historical host-disk ``$TOOLSTACK_SECRETS_DIR``. The tool id is read
from the same toolyard.toml the forwarder already loads -- the runner
mounts it in at ``$TOOLSTACK_TOOL_CONFIG`` -- so the canonical id and
the SPS-registered id are always the same value (no risk of the
hardcoded-id / toml-id drift that bit the original echo tool).
"""

from __future__ import annotations

import atexit
import os
import signal
import sys
import time
from pathlib import Path

from sps.tool_sdk import SecretClient

from .config import ConfigError, load_config
from .server import serve


DEFAULT_MAX_BODY = 20 * 1024 * 1024


# --- DIAGNOSTIC (temporary): record every signal/exit the forwarder takes so we can see
# what kills it when ECONNREFUSED hits the broker. Writes to stderr (captured to tool.log).
_LIFECYCLE_TAG = f"[lifecycle {os.getpid()} ppid={os.getppid()}]"


def _lifecycle_log(msg: str) -> None:
    sys.stderr.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
                     f"{_LIFECYCLE_TAG} {msg}\n")
    sys.stderr.flush()


def _signal_log_handler(signum, frame):
    _lifecycle_log(f"received signal signum={signum} name={signal.Signals(signum).name}")
    # Re-raise the default action so the normal shutdown / termination path runs.
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


_atexit_logged = False


def _atexit_log():
    global _atexit_logged
    if _atexit_logged:
        return
    _atexit_logged = True
    _lifecycle_log("atexit normal-return-from-main")


for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGPIPE):
    try:
        signal.signal(_sig, _signal_log_handler)
    except (ValueError, OSError):
        pass  # SIGPIPE may be unavailable in some configs

atexit.register(_atexit_log)


def main() -> None:
    config_path = Path(os.environ.get("TOOLSTACK_TOOL_CONFIG", "toolyard.toml"))
    try:
        config = load_config(config_path)
        port = _int_env("TOOLSTACK_PORT", config.port)
        if port is None:
            raise ConfigError(
                f"{config_path}: entrypoint.port: missing and TOOLSTACK_PORT is unset"
            )
        bind = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")
        timeout = _float_env("TOOLSTACK_FORWARDER_TIMEOUT", 28.0)
        max_body = _int_env("TOOLSTACK_REST_BODY_MAX", DEFAULT_MAX_BODY) or DEFAULT_MAX_BODY
    except ConfigError as exc:
        raise SystemExit(f"toolstack-forwarder: {exc}")

    secrets = SecretClient.from_env(config.tool_id)
    serve(bind, port, config, secrets, timeout=timeout, max_body=max_body).serve_forever()


def _int_env(name: str, default: int | None) -> int | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer")
    if value < 1:
        raise ConfigError(f"{name} must be positive")
    return value


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number")
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


if __name__ == "__main__":
    main()

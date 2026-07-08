"""Entrypoint for ``python3 -m toolstack_forwarder``."""

from __future__ import annotations

import os
from pathlib import Path

from .config import ConfigError, load_config
from .server import serve


DEFAULT_MAX_BODY = 20 * 1024 * 1024


def main() -> None:
    config_path = Path(os.environ.get("TOOLSTACK_TOOL_CONFIG", "toolyard.toml"))
    try:
        config = load_config(config_path)
        port = _int_env("TOOLSTACK_PORT", config.port)
        if port is None:
            raise ConfigError(f"{config_path}: entrypoint.port: missing and TOOLSTACK_PORT is unset")
        bind = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")
        secrets_dir = os.environ.get("TOOLSTACK_SECRETS_DIR", "/run/secrets")
        timeout = _float_env("TOOLSTACK_FORWARDER_TIMEOUT", 28.0)
        max_body = _int_env("TOOLSTACK_REST_BODY_MAX", DEFAULT_MAX_BODY) or DEFAULT_MAX_BODY
    except ConfigError as exc:
        raise SystemExit(f"toolstack-forwarder: {exc}")

    serve(bind, port, config, secrets_dir, timeout=timeout, max_body=max_body).serve_forever()


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

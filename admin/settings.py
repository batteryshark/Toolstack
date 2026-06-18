"""Where the admin app keeps its own files, and a few login knobs.

Login credentials (the scrypt password hash and the HMAC session secret) live
under the XDG config dir; supervisor state and the broker log live under the XDG
state dir — mirroring how the rest of Toolstack is laid out. Secret files are
written ``0600``. None of this is the broker's data (that is the SQLite file the
``BrokerRunConfig`` points at).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def _xdg(env: str, default: str) -> Path:
    return Path(os.environ.get(env) or os.path.expanduser(default))


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", "~/.config") / "toolstack" / "admin"


def state_dir() -> Path:
    return _xdg("XDG_STATE_HOME", "~/.local/state") / "toolstack" / "admin"


def password_hash_file() -> Path:
    return config_dir() / "password.hash"


def session_secret_file() -> Path:
    return config_dir() / "session.key"


def admin_username() -> str:
    return os.environ.get("TOOLSTACK_ADMIN_USERNAME", "admin")


def admin_host() -> str:
    """The admin's bind host — 127.0.0.1 by default. Override with `TOOLSTACK_ADMIN_HOST`
    ONLY inside a container (must bind 0.0.0.0 to be reachable), where the boundary moves
    to Docker's publish mapping (publish to 127.0.0.1:<port> on the host only). Never set
    it to 0.0.0.0 on a bare host. Mirrors the broker's `TOOLSTACK_BROKER_HOST`."""
    return os.environ.get("TOOLSTACK_ADMIN_HOST") or "127.0.0.1"


def session_ttl_seconds() -> int:
    return int(os.environ.get("TOOLSTACK_ADMIN_SESSION_TTL", str(12 * 60 * 60)))


def tool_secrets_file() -> str:
    """The dev secrets file the toolyard resolves tool secrets from — the same
    ``TOOLSTACK_SECRETS_FILE`` default the ``toolyard`` CLI uses."""
    return os.environ.get("TOOLSTACK_SECRETS_FILE", "secrets.toml")


def tool_runner_backend() -> str:
    """The toolyard runner backend (process/docker), matching the CLI's default."""
    return os.environ.get("TOOLSTACK_RUNNER", "process")


def secret_backend() -> str:
    """The active secret backend the toolyard resolves tool secrets from
    (file/vault/infisical). A deployment-wide setting, not per-tool."""
    return os.environ.get("TOOLSTACK_SECRET_BACKEND", "file")


def secret_backend_info() -> dict:
    """A display-only summary of how tool secrets resolve, for the tool editor. Lets the
    operator see whether secrets come from Infisical (and which project/host/env) without
    exposing any secret value."""
    name = secret_backend()
    if name == "infisical":
        return {
            "name": "infisical",
            "host": os.environ.get("TOOLSTACK_INFISICAL_HOST", ""),
            "environment": os.environ.get("TOOLSTACK_INFISICAL_ENVIRONMENT", "prod"),
            "default_vault": os.environ.get("TOOLSTACK_INFISICAL_VAULT", ""),
        }
    if name == "vault":
        return {"name": "vault",
                "path": os.environ.get("TOOLSTACK_VAULT_FILE", "") or "~/.config/toolstack/vault.json"}
    return {"name": "file", "path": tool_secrets_file()}


def _write_private(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    path.chmod(0o600)


def read_password_hash() -> str | None:
    """The stored admin password hash, or None if no password has been set."""
    path = password_hash_file()
    return path.read_text(encoding="utf-8").strip() if path.exists() else None


def write_password_hash(encoded: str) -> None:
    _write_private(password_hash_file(), encoded)


def load_or_create_session_secret() -> str:
    """Return the persisted session-signing secret, creating one on first run."""
    path = session_secret_file()
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(32)
    _write_private(path, secret)
    return secret

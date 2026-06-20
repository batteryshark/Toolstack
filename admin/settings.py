"""Where the admin app keeps its own files, and a few login knobs.

Login credentials (the scrypt password hash and the HMAC session secret) live
under the XDG config dir; supervisor state and the broker log live under the XDG
state dir — mirroring how the rest of Toolstack is laid out. Secret files are
written ``0600``. None of this is the broker's data (that is the SQLite file the
``BrokerRunConfig`` points at).
"""

from __future__ import annotations

import ipaddress
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


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def allow_nonloopback() -> bool:
    """Opt-in (``TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK=1``) required to bind the admin off loopback:
    binding 0.0.0.0 / a LAN IP on a bare host exposes the panel to the network. The container
    sets it, because there the boundary is Docker's publish-to-127.0.0.1 mapping instead."""
    return os.environ.get("TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK", "").lower() in ("1", "true", "yes")


def admin_host() -> str:
    """The admin's bind host — 127.0.0.1 by default. `TOOLSTACK_ADMIN_HOST` overrides it (only
    sensible inside a container, which must bind 0.0.0.0 and relies on Docker's
    publish-to-127.0.0.1 mapping as its boundary). A non-loopback host **fails closed** unless
    `TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK=1` is also set. Mirrors the broker's `TOOLSTACK_BROKER_HOST`."""
    host = os.environ.get("TOOLSTACK_ADMIN_HOST") or "127.0.0.1"
    if not _is_loopback(host) and not allow_nonloopback():
        raise SystemExit(
            f"refusing to bind the admin to non-loopback host {host!r} without "
            "TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK=1 — binding off 127.0.0.1 exposes the "
            "unauthenticated-by-network panel; set it only behind a tunnel/proxy you trust "
            "(and set TOOLSTACK_ADMIN_SECURE_COOKIE=1 there).")
    return host


def cookie_secure() -> bool:
    """Mark the session cookie Secure (the browser sends it only over https). Off by default —
    loopback and the container's http-behind-publish both serve plain http. Set
    ``TOOLSTACK_ADMIN_SECURE_COOKIE=1`` when the panel is reached over TLS (the recommended
    remote setup) so the session cookie can't leak over a plaintext hop."""
    return os.environ.get("TOOLSTACK_ADMIN_SECURE_COOKIE", "").lower() in ("1", "true", "yes")


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
    return rotate_session_secret()


def rotate_session_secret() -> str:
    """Replace the session-signing secret, invalidating every existing signed session. Called
    when the admin password changes so a reset also logs out any other live sessions (it takes
    effect on the next app start, which loads the secret once)."""
    secret = secrets.token_urlsafe(32)
    _write_private(session_secret_file(), secret)
    return secret

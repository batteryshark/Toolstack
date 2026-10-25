"""Password hashing, signed browser sessions, and CSRF tokens.

The password and session helpers derive from the previous broker-panel
(stdlib ``scrypt`` + HMAC, no external dependency). Passwords use
``scrypt`` because they are human-chosen and low-entropy; this is deliberately
different from broker *tokens*, which are high-entropy random and only SHA-256
hashed (see :mod:`broker.identity`).

CSRF protection uses a synchronizer token derived from the session value. A
cross-site attacker can drive the browser to POST but cannot read the session
cookie, so cannot compute a matching token; this closes a gap the old panel had.
Session and CSRF HMACs have distinct purpose prefixes; legacy tokens are rejected.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import json
import fcntl
import os

from . import settings


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 16384, 8, 1
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p)
    return "$".join(
        [
            "scrypt",
            str(n),
            str(r),
            str(p),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, raw_n, raw_r, raw_p, raw_salt, raw_digest = encoded.split("$", 5)
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(raw_salt.encode("ascii"))
        expected = base64.urlsafe_b64decode(raw_digest.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(raw_n),
            r=int(raw_r),
            p=int(raw_p),
        )
    except Exception:
        return False
    return hmac.compare_digest(actual, expected)


def sign_session(username: str, secret: str, ttl_seconds: int) -> str:
    expires_at = int(time.time()) + ttl_seconds
    message = f"{username}|{expires_at}|{secrets.token_hex(16)}"
    signature = hmac.new(secret.encode("utf-8"), ("session|" + message).encode("utf-8"), hashlib.sha256).hexdigest()
    raw = f"{message}|{signature}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def verify_session(cookie: str | None, secret: str) -> str | None:
    if not isinstance(cookie, str) or not cookie:
        return None
    try:
        decoded = base64.urlsafe_b64decode(cookie.encode("ascii")).decode("utf-8")
        username, raw_expires, session_id, signature = decoded.split("|")
        expires_at = int(raw_expires)
        if len(session_id) != 32 or any(c not in "0123456789abcdef" for c in session_id):
            return None
    except Exception:
        return None
    if expires_at < int(time.time()):
        return None
    message = f"{username}|{expires_at}|{session_id}"
    expected = hmac.new(secret.encode("utf-8"), ("session|" + message).encode("utf-8"), hashlib.sha256).hexdigest()
    if not signature.isascii() or not hmac.compare_digest(signature, expected):
        return None
    try:
        if session_id in _revoked_sessions():
            return None
    except (OSError, ValueError, TypeError):
        return None
    return username


def _revoked_sessions() -> dict:
    path = settings.config_dir() / "revoked-sessions.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict) or any(not isinstance(v, int) for v in data.values()):
        raise ValueError("invalid session revocations")
    return data


def revoke_session(token: str, secret: str) -> None:
    """Persist revocation until expiry, serializing writers across admin processes."""
    directory = settings.config_dir()
    settings._private_directory(directory)
    fd = os.open(directory / "revoked-sessions.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if verify_session(token, secret) is None:
            return
        _, expiry, session_id, _ = base64.urlsafe_b64decode(token).decode().split("|")
        revoked = {key: value for key, value in _revoked_sessions().items() if value >= int(time.time())}
        if len(revoked) >= 4096:
            # Bound state without making any revoked token valid again.
            settings.rotate_session_secret()
            revoked = {}
        else:
            revoked[session_id] = int(expiry)
        settings._write_private(directory / "revoked-sessions.json", json.dumps(revoked))
    finally:
        os.close(fd)


def csrf_token(session_value: str, secret: str) -> str:
    """A CSRF token bound to one session, derived via HMAC over the session cookie."""
    return hmac.new(
        secret.encode("utf-8"), ("csrf-v1|" + session_value).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_csrf(token: str | None, session_value: str | None, secret: str) -> bool:
    if (not isinstance(token, str) or not token or not token.isascii()
            or not isinstance(session_value, str) or not session_value):
        return False
    try:
        expected = csrf_token(session_value, secret)
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(token, expected)

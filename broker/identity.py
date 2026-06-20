"""Caller identity (the Identity module seam).

Owns callers and their bearer tokens. Tokens are stored only as SHA-256 hashes;
the raw token is shown once at creation and never persisted or logged. SHA-256
(not bcrypt) is appropriate because tokens are high-entropy random secrets, not
human-chosen passwords.

Authentication fails closed: an absent, malformed, unknown, or revoked token
resolves to no caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Caller:
    id: int
    name: str


def bearer_token(authorization_header: str | None) -> str | None:
    """Extract a bearer token from an Authorization header, or None.

    Kept separate so callers can note a token's *presence* for audit without ever
    handling its value, and so hashing happens in exactly one place.
    """
    if not authorization_header:
        return None
    scheme, _, value = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_fingerprint(authorization_header: str | None) -> str | None:
    """A short, non-reversible fingerprint of the presented bearer (first 12 hex of its
    SHA-256), or None if no bearer is present. For audit only; it lets repeated use of
    the same credential (valid or not) be correlated without ever logging the token."""
    token = bearer_token(authorization_header)
    return hash_token(token)[:12] if token else None


def authenticate(store, authorization_header: str | None) -> Caller | None:
    """Resolve a live caller from the Authorization header, or None (deny).

    ``store`` is the broker Store; passed in rather than imported to keep this
    module free of persistence concerns.
    """
    token = bearer_token(authorization_header)
    if token is None:
        return None
    return store.caller_by_token_hash(hash_token(token))

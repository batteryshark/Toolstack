"""The JSON-line protocol primitives shared by SPS server + handlers.

The wire is one JSON object per line in each direction. No HTTP, no
persistent connections, no binary framing. This module has NO
dependencies on `handlers` -- just stdlib `hmac`/`json` and the
constants the spec pins.

Auth comparison uses `hmac.compare_digest` on the body field
(`spsecret` / `esecret`), not on an HTTP header.

Body caps: an oversized request cannot hold a connection forever.
SOCKET_TIMEOUT is set on the per-connection listener below.
"""
from __future__ import annotations

import hmac
import json
from typing import Any

# 1 MiB -- the wire spec's explicit cap.
MAX_BODY_BYTES = 1_048_576
READLINE_LIMIT = MAX_BODY_BYTES + 1  # so we can detect overflow without truncation

# The fixed set of error messages per the guidance. Errors carry only this
# string and never any secret value, credential, or backend response body.
MESSAGE_SET = {
    "Bad request",
    "Unauthorized",
    "Not found",
    "Not writable",
    "Backend error",
}


class OversizedBodyError(ValueError):
    """The request body exceeded MAX_BODY_BYTES."""


def constant_time_eq(a: str, b: str) -> bool:
    """Constant-time equality for auth secret comparisons."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def read_one_json(infile) -> dict[str, Any]:
    """Read one JSON line from `infile`. Handles both text and binary file
    modes (socketserver opens binary for sockets, but tests/IO wrappers
    may use text). The wire format is UTF-8 bytes + `\\n` either way.
    Raises `OversizedBodyError` if the line exceeds MAX_BODY_BYTES; raises
    `ValueError` on invalid JSON or non-UTF-8 input. Returns `{}` on EOF.
    """
    raw = infile.readline(READLINE_LIMIT)
    if not raw:
        return {}
    if isinstance(raw, bytes):
        if raw.strip() == b"":
            return {}
        if len(raw) > MAX_BODY_BYTES:
            raise OversizedBodyError(f"body exceeds {MAX_BODY_BYTES} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"body not UTF-8: {exc}") from exc
    else:
        if raw.strip() == "":
            return {}
        if len(raw) > MAX_BODY_BYTES:
            raise OversizedBodyError(f"body exceeds {MAX_BODY_BYTES} bytes")
        text = raw
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"body not valid JSON: {exc}") from exc


def write_one_json(outfile, obj: dict) -> None:
    """Write one JSON object followed by `\\n`. Flushes immediately so the
    client can rely on read-complete without further buffering. The output
    file may be text or binary; we emit bytes so the wire is identical
    regardless of the caller's mode."""
    payload = (json.dumps(obj) + "\n").encode("utf-8")
    try:
        outfile.write(payload)
    except TypeError:
        # Text-mode file: caller passed a non-binary. Fall back to str.
        outfile.write(json.dumps(obj) + "\n")
    outfile.flush()


def read_one_json(infile) -> dict[str, Any]:
    """Read one JSON line from `infile`. Raises `OversizedBodyError` if the
    line exceeds MAX_BODY_BYTES; raises `ValueError` on invalid JSON.
    Returns `{}` (sentinel) if the line is empty/EOF."""
    raw = infile.readline(READLINE_LIMIT)
    if not raw:
        return {}
    if isinstance(raw, bytes):
        if len(raw) > MAX_BODY_BYTES:
            raise OversizedBodyError(f"body exceeds {MAX_BODY_BYTES} bytes")
        try:
            return json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError(f"body not UTF-8: {exc}") from exc
    if len(raw) > MAX_BODY_BYTES:
        raise OversizedBodyError(f"body exceeds {MAX_BODY_BYTES} bytes")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"body not valid JSON: {exc}") from exc


def err_envelope(message: str) -> dict[str, Any]:
    if message not in MESSAGE_SET:
        raise ValueError(f"unknown error message {message!r}")
    return {"status": "error", "message": message}

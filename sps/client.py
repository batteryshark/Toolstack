"""SPS TLS/TCP client used by the tool runner and by tools themselves.

Per call: one socket connection, one TLS handshake (verifying the server cert
against `ca_file`), one JSON-line request, one JSON-line response, close.
No persistent connections or pipelining -- matches the wire spec.
"""
from __future__ import annotations

import json
import socket
import ssl
import threading
from typing import Iterable
from .config import strict_bool
from .transport import Budget, valid_timeout, _Socket, MAX_RESPONSE, connect_socket


class SPSError(RuntimeError):
    """Base for SPS client errors."""


class AuthError(SPSError):
    """The SPS rejected the call with `Unauthorized`."""


class NotFound(SPSError):
    """The SPS returned `Not found` (tool or secret name)."""


class NotWritable(SPSError):
    """The SPS returned `Not writable`."""


class BackendError(SPSError):
    """The SPS returned `Backend error`."""


class BadResponse(SPSError):
    """The response envelope was malformed (Bad request or otherwise)."""


class TransportError(SPSError, OSError):
    """Socket/TLS failure; also OSError-compatible for existing callers."""


# Map each fixed error message to the typed exception class.
_ERROR_MAP = {
    "Unauthorized": AuthError,
    "Not found": NotFound,
    "Not writable": NotWritable,
    "Backend error": BackendError,
    "Bad request": BadResponse,
}


def _default_context(**kwargs):
    try:
        return ssl.create_default_context(**kwargs)
    except OSError as exc:
        raise TransportError(type(exc).__name__) from None


class SPSClient:
    def __init__(self, host: str, port: int, *, sp_secret: str | None = None,
                 esecret: str | None = None, ca_file: str | None = None,
                 verify: bool = True, timeout: float = 15.0,
                 max_response_bytes: int = MAX_RESPONSE) -> None:
        self.host = host
        self.port = port
        self.sp_secret = sp_secret
        self.esecret = esecret
        self._timeout = valid_timeout(timeout)
        if type(max_response_bytes) is not int or not 1024 <= max_response_bytes <= 32 * 1024 * 1024:
            raise ValueError("invalid response limit")
        self._max_response_bytes = max_response_bytes
        verify = strict_bool(verify)
        # Build the client TLS context. If `verify` is False (dev with
        # self-signed cert), accept any cert. Otherwise require `ca_file`.
        self._ctx: ssl.SSLContext | None
        if not verify:
            ctx = _default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ctx = ctx
        elif ca_file:
            self._ctx = _default_context(cafile=ca_file)
        else:
            self._ctx = _default_context()  # system trust store
        self._lock = threading.Lock()

    # ---- runner-facing (SP) -----------------------------------------------
    def register(self, tool_id: str, esecret: str, cs_tuples: Iterable[dict]) -> None:
        body = list(cs_tuples)
        self._call({"op": "register",
                     "spsecret": self._require("sp"),
                     "toolid": tool_id,
                     "esecret": esecret,
                     "secrets": body})

    def unregister(self, tool_id: str) -> None:
        self._call({"op": "unregister",
                     "spsecret": self._require("sp"),
                     "toolid": tool_id})

    # ---- tool-facing (ES) -----------------------------------------------
    def get_secrets(self, tool_id: str) -> dict:
        body = self._call({"op": "get_secrets",
                            "toolid": tool_id,
                            "esecret": self._require("es")})
        self._validate_secrets(body)
        return body

    def get_secret(self, tool_id: str, name: str) -> str:
        body = self._call({"op": "get_secret",
                            "toolid": tool_id,
                            "name": name,
                            "esecret": self._require("es")})
        self._validate_secrets(body)
        if name not in body["secrets"]:
            raise BadResponse("missing requested secret")
        return body["secrets"][name]

    @staticmethod
    def _validate_secrets(body):
        if (not isinstance(body, dict) or body.get("status") != "ok" or
                not isinstance(body.get("secrets"), dict) or
                any(not isinstance(k, str) or not isinstance(v, str)
                    for k, v in body["secrets"].items())):
            raise BadResponse("invalid secret response")

    def write_secret(self, tool_id: str, name: str, value: str) -> None:
        self._call({"op": "write_secret",
                     "toolid": tool_id,
                     "name": name,
                     "value": value,
                     "esecret": self._require("es")})

    # ---- liveness/identity --------------------------------------------------
    def ping(self) -> dict:
        """Liveness/identity probe. No secret required."""
        return self._call({"op": "ping"})

    # ---- private ------------------------------------------------------------
    def _require(self, kind: str) -> str:
        val = self.sp_secret if kind == "sp" else self.esecret
        if val is None:
            raise SPSError(f"{kind} secret not configured on SPSClient")
        return val

    def _call(self, msg: dict) -> dict:
        # Serialise: one connection at a time per client instance. This is
        # not a multi-thread client; the wire spec is one-message-per-socket
        # and per-process usages are short-lived.
        budget = Budget(self._timeout, self._max_response_bytes)
        if not self._lock.acquire(timeout=budget.remaining()):
            raise TransportError("SPS operation deadline exceeded")
        try:
            payload = (json.dumps(msg) + "\n").encode("utf-8")
            try:
                with connect_socket(self.host, self.port, budget) as raw_sock:
                    budget.remaining()
                    assert self._ctx is not None
                    raw_sock.settimeout(budget.idle())
                    with self._ctx.wrap_socket(raw_sock, server_hostname=self.host,
                                               do_handshake_on_connect=False) as s:
                        s.settimeout(budget.idle())
                        s.do_handshake()
                        budget.remaining()
                        bounded = _Socket(s, budget)
                        bounded.sendall(payload)
                        with bounded.makefile("rb") as f:
                            line = f.readline(self._max_response_bytes + 1)
                        budget.count(len(line))
                        if not line.endswith(b"\n"):
                            raise ValueError("invalid response framing")
                        resp = json.loads(line.decode("utf-8"))
            except OSError as exc:
                raise TransportError(type(exc).__name__) from None
            except ValueError:
                raise BadResponse("invalid response framing or JSON") from None
            if not isinstance(resp, dict):
                raise BadResponse("invalid response envelope")
            status = resp.get("status")
            if status == "ok":
                return resp
            if status == "error":
                msg_str = resp.get("message")
                if not isinstance(msg_str, str) or msg_str not in _ERROR_MAP:
                    raise BadResponse("invalid error response")
                raise _ERROR_MAP[msg_str](msg_str)
            raise BadResponse("invalid response envelope")
        finally:
            self._lock.release()

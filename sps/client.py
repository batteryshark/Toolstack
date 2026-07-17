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


# Map each fixed error message to the typed exception class.
_ERROR_MAP = {
    "Unauthorized": AuthError,
    "Not found": NotFound,
    "Not writable": NotWritable,
    "Backend error": BackendError,
    "Bad request": BadResponse,
}


class SPSClient:
    def __init__(self, host: str, port: int, *, sp_secret: str | None = None,
                 esecret: str | None = None, ca_file: str | None = None,
                 verify: bool = True) -> None:
        self.host = host
        self.port = port
        self.sp_secret = sp_secret
        self.esecret = esecret
        # Build the client TLS context. If `verify` is False (dev with
        # self-signed cert), accept any cert. Otherwise require `ca_file`.
        self._ctx: ssl.SSLContext | None
        if not verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ctx = ctx
        elif ca_file:
            self._ctx = ssl.create_default_context(cafile=ca_file)
        else:
            self._ctx = ssl.create_default_context()  # system trust store
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
        return self._call({"op": "get_secrets",
                            "toolid": tool_id,
                            "esecret": self._require("es")})

    def get_secret(self, tool_id: str, name: str) -> str:
        body = self._call({"op": "get_secret",
                            "toolid": tool_id,
                            "name": name,
                            "esecret": self._require("es")})
        return body.get("secrets", {}).get(name, "")

    def write_secret(self, tool_id: str, name: str, value: str) -> None:
        self._call({"op": "write_secret",
                     "toolid": tool_id,
                     "name": name,
                     "value": value,
                     "esecret": self._require("es")})

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
        with self._lock:
            payload = (json.dumps(msg) + "\n").encode("utf-8")
            with socket.create_connection((self.host, self.port), timeout=15) as raw_sock:
                assert self._ctx is not None
                with self._ctx.wrap_socket(raw_sock, server_hostname=self.host) as s:
                    s.sendall(payload)
                    f = s.makefile("rb")
                    line = f.readline()
            if not line:
                raise SPSError("server closed connection without a response")
            try:
                resp = json.loads(line.decode("utf-8").rstrip("\n"))
            except json.JSONDecodeError as exc:
                raise SPSError(f"server returned invalid JSON: {exc}")
            status = resp.get("status")
            if status == "ok":
                return resp
            if status == "error":
                msg_str = resp.get("message", "Bad request")
                raise _ERROR_MAP.get(msg_str, SPSError)(msg_str)
            raise SPSError(f"server returned unknown envelope: {resp}")

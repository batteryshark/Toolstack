"""Outbound HTTP client for the rest forwarder."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from .request_builder import OutboundRequest


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}


def send(request: OutboundRequest, timeout: float, max_body: int) -> dict:
    req = urllib.request.Request(request.url, data=request.body, headers=request.headers, method=request.method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return _response_envelope(resp.status, resp.headers, _read_capped(resp, max_body), max_body)
    except urllib.error.HTTPError as exc:
        try:
            return _response_envelope(exc.code, exc.headers, _read_capped(exc, max_body), max_body)
        finally:
            exc.close()
    except urllib.error.URLError as exc:
        host = urllib.parse.urlsplit(request.url).hostname or ""
        return {"error": "outbound_unreachable", "host": host, "reason": str(exc.reason)}


def _read_capped(resp, max_body: int) -> bytes | None:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read(min(65536, max_body + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_body:
            return None
    return b"".join(chunks)


def _response_envelope(status: int, headers, body: bytes | None, max_body: int) -> dict:
    if body is None:
        return {"error": "response_too_large", "limit_bytes": max_body}
    clean_headers = {}
    for name, value in headers.items():
        lname = name.lower()
        if lname == "set-cookie" or lname in _HOP_BY_HOP:
            continue
        clean_headers[lname] = value
    return {
        "status": int(status),
        "headers": clean_headers,
        "body": body.decode("utf-8", "replace"),
    }

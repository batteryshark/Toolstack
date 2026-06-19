"""REST-KV tool — a small REST-compliant key-value store (the template for a
``type = "rest"`` passthrough tool).

A rest tool is just an ordinary HTTP service. The broker does NOT terminate a custom
protocol for it: the agent calls ``kv.GET`` / ``kv.POST`` / ``kv.PUT`` / ``kv.PATCH`` /
``kv.DELETE`` with ``{path, body, query}``, and the broker forwards the raw
``<verb> 127.0.0.1:<port><path>`` request straight through, returning this service's
status + body. So everything below is plain REST — the same code would work behind any
reverse proxy. Resources:

    GET    /items            list all keys
    GET    /items/<key>      read one key            (404 if absent)
    POST   /items            create {key, value}     (409 if it exists, 400 if no key)
    PUT    /items/<key>      upsert {value}          (201 created / 200 replaced)
    PATCH  /items/<key>      update {value}          (404 if absent)
    DELETE /items/<key>      remove                  (404 if absent)

The store is in-memory (resets on restart) — it's a demo. Broker request context arrives
in headers (``X-Toolstack-Request-Id`` / ``X-Toolstack-Caller``), and the same optional
``broker_secret`` defense-in-depth check as the other templates applies. Stdlib only.
"""

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

SECRETS_DIR = os.environ.get("TOOLSTACK_SECRETS_DIR", "/run/secrets")
PORT = int(os.environ.get("TOOLSTACK_PORT", "4621"))
BIND = os.environ.get("TOOLSTACK_BIND", "127.0.0.1")

STORE: dict = {}  # in-memory key -> value (demo; resets on restart)


def secret(name: str) -> str:
    with open(os.path.join(SECRETS_DIR, name), encoding="utf-8") as f:
        return f.read().strip()


def verify_broker(headers) -> bool:
    """Opt-in shared-secret check, identical in contract to the other tool templates."""
    try:
        expected = secret("broker_secret")
    except FileNotFoundError:
        return True
    if not expected:
        return True
    presented = headers.get("X-Toolstack-Secret", "")
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


class _Handler(BaseHTTPRequestHandler):
    server_version = "rest-kv-tool"
    sys_version = ""

    # -- helpers -----------------------------------------------------------------
    def _route(self):
        """Classify the path: ('collection', None) for /items, ('item', key) for
        /items/<key>, else ('bad', None)."""
        parts = urlparse(self.path).path.strip("/").split("/")
        if not parts or parts[0] != "items":
            return ("bad", None)
        if len(parts) == 1:
            return ("collection", None)
        if len(parts) == 2 and parts[1]:
            return ("item", parts[1])
        return ("bad", None)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return None  # signals 400

    def _send(self, status: int, obj=None):
        payload = b"" if obj is None else json.dumps(obj).encode("utf-8")
        self.send_response(status)
        if payload:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _guard(self) -> bool:
        if not verify_broker(self.headers):
            self._send(401, {"error": "unauthorized"})
            return False
        return True

    # -- verbs -------------------------------------------------------------------
    def do_GET(self):
        if not self._guard():
            return
        kind, key = self._route()
        if kind == "collection":
            return self._send(200, {"items": [{"key": k, "value": v} for k, v in STORE.items()]})
        if kind == "item":
            if key in STORE:
                return self._send(200, {"key": key, "value": STORE[key]})
            return self._send(404, {"error": "not_found", "key": key})
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        if not self._guard():
            return
        if self._route()[0] != "collection":
            return self._send(404, {"error": "not_found"})
        body = self._read_json()
        if body is None:
            return self._send(400, {"error": "invalid_json"})
        key = body.get("key")
        if not isinstance(key, str) or not key:
            return self._send(400, {"error": "key_required"})
        if key in STORE:
            return self._send(409, {"error": "exists", "key": key})
        STORE[key] = body.get("value")
        return self._send(201, {"key": key, "value": STORE[key]})

    def do_PUT(self):
        if not self._guard():
            return
        kind, key = self._route()
        if kind != "item":
            return self._send(404, {"error": "not_found"})
        body = self._read_json()
        if body is None:
            return self._send(400, {"error": "invalid_json"})
        created = key not in STORE
        STORE[key] = body.get("value")
        return self._send(201 if created else 200, {"key": key, "value": STORE[key]})

    def do_PATCH(self):
        if not self._guard():
            return
        kind, key = self._route()
        if kind != "item" or key not in STORE:
            return self._send(404, {"error": "not_found", "key": key})
        body = self._read_json()
        if body is None:
            return self._send(400, {"error": "invalid_json"})
        if "value" in body:
            STORE[key] = body["value"]
        return self._send(200, {"key": key, "value": STORE[key]})

    def do_DELETE(self):
        if not self._guard():
            return
        kind, key = self._route()
        if kind != "item" or key not in STORE:
            return self._send(404, {"error": "not_found", "key": key})
        del STORE[key]
        return self._send(200, {"deleted": key})

    def log_message(self, *args):
        pass


def main():
    HTTPServer((BIND, PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()

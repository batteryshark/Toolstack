"""HTTP server for broker -> rest forwarder calls."""

from __future__ import annotations

import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from . import outbound
from .config import RestConfig
from .request_builder import RequestBuildError, build_request, read_secret
from .rules import RuleError, apply_secret_update_rules


def serve(bind: str, port: int, config: RestConfig, secrets_dir: str | Path,
          timeout: float, max_body: int) -> HTTPServer:
    return HTTPServer((bind, port), _handler(config, Path(secrets_dir), timeout, max_body))


def _handler(config: RestConfig, secrets_dir: Path, timeout: float, max_body: int):
    envelope_max = max(max_body * 2 + 65536, 1024 * 1024)
    handler_timeout = timeout

    class Handler(BaseHTTPRequestHandler):
        server_version = "toolstack-forwarder"
        sys_version = ""
        timeout = handler_timeout

        def do_POST(self) -> None:
            if self.path != "/sendrequest":
                return self._reply(404, {"error": "not_found"})
            ok, err = self._verify_channel_secret()
            if not ok:
                return self._reply(401, {"error": err})

            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._reply(400, {"error": "invalid_content_length"})
            if length < 0 or length > envelope_max:
                return self._reply(413, {"error": "body_too_large", "limit_bytes": envelope_max})
            raw = self.rfile.read(length) if length else b""
            try:
                envelope = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return self._reply(400, {"error": "invalid_json"})
            if not isinstance(envelope, dict):
                return self._reply(400, {"error": "invalid_envelope", "detail": "body must be a JSON object"})
            op = envelope.get("op")
            if not isinstance(op, str):
                return self._reply(400, {"error": "invalid_envelope", "detail": "op must be a string"})
            arguments = envelope.get("arguments", {})
            try:
                req = build_request(config, op, arguments, secrets_dir, max_body)
            except RequestBuildError as exc:
                status = 400 if exc.code != "unknown_op" else 404
                return self._reply(status, exc.envelope())
            result = outbound.send(req, timeout=timeout, max_body=max_body)
            if "status" in result:
                try:
                    apply_secret_update_rules(config.operations[op], result)
                except RuleError as exc:
                    return self._reply(502, exc.envelope())
            status = 502 if "error" in result else 200
            self._reply(status, result)

        def do_GET(self) -> None:
            self._reply(405, {"error": "method_not_allowed"})

        do_PUT = do_PATCH = do_DELETE = do_GET

        def _verify_channel_secret(self) -> tuple[bool, str]:
            try:
                expected = read_secret(secrets_dir, "broker_secret")
            except RequestBuildError:
                return True, ""
            if not expected:
                return True, ""
            presented = (self.headers.get("X-Toolstack-Secret") or "").strip()
            if not hmac.compare_digest(presented, expected):
                return False, "channel_secret_mismatch"
            return True, ""

        def _reply(self, status: int, obj: dict) -> None:
            payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args) -> None:
            pass

    return Handler

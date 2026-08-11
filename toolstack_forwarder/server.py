"""HTTP server for broker -> rest forwarder calls."""

from __future__ import annotations

import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from sps.tool_sdk import SecretClient

from . import outbound
from .config import Operation, RestConfig
from .request_builder import RequestBuildError, build_request
from .rules import RuleError, apply_secret_update_rules

_REDACTED_BODY_JSON = '{"message":"response redacted for this operation due to config in toolserver"}'
_REDACTED_BODY_TEXT = "response redacted for this operation due to config in toolserver"
_REDACTED_HEADERS = {"X-ToolStack-Security": "headers redacted for this operation due to config in toolserver"}


def serve(bind: str, port: int, config: RestConfig, secrets: SecretClient,
          timeout: float, max_body: int) -> HTTPServer:
    return HTTPServer((bind, port), _handler(config, secrets, timeout, max_body))


def redact_response(op: Operation, result: dict) -> None:
    """Replace caller-facing response parts the operation marks as sensitive, in place.

    Runs *after* secret-update rules, so writebacks still extract from the real body while the
    caller receives only placeholders. Body redaction reads the original Content-Type (JSON gets
    a JSON message, everything else a plain string) and must happen before header redaction wipes
    that header."""
    if op.redact_response_body:
        ctype = str(result.get("headers", {}).get("content-type", "")).lower()
        result["body"] = _REDACTED_BODY_JSON if "json" in ctype else _REDACTED_BODY_TEXT
    if op.redact_response_headers:
        result["headers"] = dict(_REDACTED_HEADERS)


def _handler(config: RestConfig, secrets: SecretClient, timeout: float, max_body: int):
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
            # Secret-refresh ops are broker-injected for tools with [[secrets]] declared
            # (broker/registry.py). Handle them locally on the forwarder's SPS-backed
            # SecretClient -- no upstream call, no proxy needed. The broker treats these
            # as risk="read" ops; we return only the refreshed name list (or length), never
            # the value, so the secret never crosses the wire back to the broker.
            if op == "refresh":
                secrets.refresh_all()
                return self._reply(200, {"status": "ok", "refreshed": list(secrets.names())})
            if op == "refresh_one":
                target = arguments.get("name") if isinstance(arguments, dict) else None
                if not isinstance(target, str) or not target:
                    return self._reply(400, {
                        "error": "invalid_envelope",
                        "detail": "refresh_one: 'name' argument is required",
                    })
                try:
                    new_value = secrets.refresh(target)
                except KeyError as exc:
                    return self._reply(404, {"error": "unknown_secret", "detail": str(exc)})
                return self._reply(200, {"status": "ok", "refreshed": [target], "len": len(new_value)})
            try:
                req = build_request(config, op, arguments, secrets, max_body)
            except RequestBuildError as exc:
                status = 400 if exc.code != "unknown_op" else 404
                return self._reply(status, exc.envelope())
            print(f"outbound {config.tool_id}/{op} {req.url}", flush=True)
            result = outbound.send(req, timeout=timeout, max_body=max_body)
            if "status" in result:
                try:
                    apply_secret_update_rules(config.operations[op], result, secrets)
                except RuleError as exc:
                    return self._reply(502, exc.envelope())
                redact_response(config.operations[op], result)
            status = 502 if "error" in result else 200
            self._reply(status, result)

        def do_GET(self) -> None:
            self._reply(405, {"error": "method_not_allowed"})

        do_PUT = do_PATCH = do_DELETE = do_GET

        def _verify_channel_secret(self) -> tuple[bool, str]:
            # The channel credential is the E_SECRET the runner minted for
            # this tool. It arrives as `X-Toolstack-Secret` from the broker,
            # sourced from the toolyard state file (Phase 4). The tool
            # compares the header against $TOOLSTACK_E_SECRET (set by the
            # runner at start); absent -> feature off (Phase 5: no more
            # FS-fallback `broker_secret` file).
            import os as _os
            expected = _os.environ.get("TOOLSTACK_E_SECRET") or ""
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

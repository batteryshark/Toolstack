"""Tool runtime (the execution seam): forward an approved call to the tool
container on ``127.0.0.1:<port>``.

The broker attaches NO secrets — the tool already has its own, resolved by the
toolyard at container start. The broker adds ``broker_request_id`` and the caller
name so the tool has request context. Unreachable or non-2xx tools raise, which
the request lifecycle maps to 502.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .registry import ToolOp


class HttpRuntime:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def execute(self, tool_op: ToolOp, arguments: dict, request_id: int, caller_name: str) -> dict:
        url = f"http://127.0.0.1:{tool_op.port}/v1/actions/{tool_op.op}"
        payload = json.dumps(
            {
                "arguments": arguments,
                "broker_request_id": request_id,
                "caller": {"name": caller_name},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError(f"tool returned HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"tool unreachable: {exc.reason}")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError("tool returned non-JSON")

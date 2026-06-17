"""Tool runtime (the execution seam): forward an approved call to the tool
container on ``127.0.0.1:<port>``.

The broker attaches NO workload secrets — the tool already has its own, resolved
by the toolyard at container start. The broker adds ``broker_request_id`` and the
caller name so the tool has request context.

As optional defense in depth, the broker may present a per-tool **shared secret**
(the ``X-Toolstack-Secret`` header) so the tool can prove the call came from the
broker — not from another loopback process that merely guessed the tool's port and
called it directly, bypassing policy and approval. The secret is the broker's own
*channel* credential for this hop; it is NOT a workload secret (the broker still
never reads the secret backend). It is opt-in per tool: with none configured the
header is absent and the tool-side check stays off, so existing tools are
unaffected. See ``_env_tool_secret`` and ``docs/message-contracts.md``.

Unreachable or non-2xx tools raise, which the request lifecycle maps to 502.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from .registry import ToolOp


def _env_tool_secret(tool_id: str) -> str | None:
    """The shared secret the broker presents to ``tool_id``, read from the env var
    ``TOOLSTACK_TOOL_SECRET_<TOOL>`` (id upper-cased, runs of non-alphanumerics collapsed
    to a single ``_`` so e.g. ``apple-calendar`` -> ``TOOLSTACK_TOOL_SECRET_APPLE_CALENDAR``).

    Returns None when unset or empty (after stripping) — the feature is opt-in, so an
    unconfigured tool gets no header. The value is **stripped of surrounding whitespace**
    so it matches the tool side, which reads its copy through the same strip (a stray
    trailing newline in the env must not silently 401 every call).

    The operator provisions the SAME value in two places: this env var (so the broker
    sends it) and the tool's secret backend (so the toolyard injects it for the tool to
    verify against). Note the id->env mapping is not injective: ids that differ only in
    case or in non-alphanumeric runs (``apple-calendar`` vs ``apple.calendar``) collapse to
    the same env var — keep tool ids distinct under this normalization. A collision only
    means the two tools share one channel secret, never that calls cross-wire (each tool
    still listens on its own loopback port)."""
    key = "TOOLSTACK_TOOL_SECRET_" + re.sub(r"[^A-Z0-9]+", "_", tool_id.upper())
    return (os.environ.get(key) or "").strip() or None


class HttpRuntime:
    def __init__(self, timeout: float = 30.0, tool_secret=_env_tool_secret) -> None:
        self._timeout = timeout
        self._tool_secret = tool_secret

    def execute(self, tool_op: ToolOp, arguments: dict, request_id: int, caller_name: str) -> dict:
        url = f"http://127.0.0.1:{tool_op.port}/v1/actions/{tool_op.op}"
        payload = json.dumps(
            {
                "arguments": arguments,
                "broker_request_id": request_id,
                "caller": {"name": caller_name},
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        secret = self._tool_secret(tool_op.tool)
        if secret:
            headers["X-Toolstack-Secret"] = secret
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
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

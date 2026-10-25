"""toolstack MCP server: exposes the broker's tools to an MCP-native agent.

A minimal stdio JSON-RPC (MCP) server: `tools/list` maps the caller's allowed broker
ops to MCP tools (with input schemas from the op's declared args), and `tools/call`
forwards to the broker, blocking on approval and returning the result (plus the
approver's note). The agent passes a structured `arguments` object, so there is no shell and no
quoting breakage. Run it as an MCP server command: `python3 -m client.mcp_server`.

Review ops advertise an optional `_reason` string in their input schema, the MCP
analogue of the CLI's `--reason`. `tools/call` pulls `_reason` out of the arguments
(it is never forwarded to the tool). It is private pending-request metadata,
never shown to the human approver or copied into audit text.

Config (env): TOOLSTACK_URL, TOOLSTACK_TOKEN / TOOLSTACK_TOKEN_FILE (shared with the
CLI). Stdlib only.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error

from .toolstack import _FAIL, _WAITING, _send
import math
from http.client import HTTPException

PROTOCOL_VERSION = "2024-11-05"
_JSON_TYPES = {"string", "integer", "number", "boolean", "object", "array"}


def _call(method: str, path: str, body=None, *, idempotency_key=None):
    # Same broker call as the CLI (client.toolstack._send); only the unreachable
    # case differs: surface it as a JSON-RPC error rather than exiting.
    try:
        return _send(method, path, body, idempotency_key=idempotency_key) if idempotency_key is not None else _send(method, path, body)
    except urllib.error.URLError as exc:
        raise RuntimeError("broker unreachable; outcome may be unknown; never retry with a new key") from None


def _input_schema(args: list) -> dict:
    props = {}
    required = []
    for a in args:
        jtype = a.get("type", "string")
        props[a["name"]] = {"type": jtype if jtype in _JSON_TYPES else "string",
                            "description": a.get("description", "")}
        if a.get("required"):
            required.append(a["name"])
    if not props:
        return {"type": "object"}  # permissive: tool validates
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _with_reason(schema: dict) -> dict:
    """Advertise the optional `_reason` justification on a review tool's input schema.
    It is legacy private metadata, stripped before the tool runs and never
    included in the approval summary or audit text."""
    props = dict(schema.get("properties", {}))
    props["_reason"] = {
        "type": "string",
        "description": ("Legacy private request metadata; omitted from approval and audit text. "
                         "Not passed to the tool. Do not include secrets."),
    }
    return {**schema, "type": "object", "properties": props}


class _MethodNotFound(Exception):
    pass


class Server:
    def __init__(self, poll_timeout: float = 300.0) -> None:
        self._names: dict[str, tuple[str, str]] = {}  # mcp tool name -> (tool, op)
        self._poll_timeout = poll_timeout

    def dispatch(self, method: str, params: dict):
        if method == "initialize":
            return {
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "toolstack", "version": "0.1.0"},
                "instructions": 'Supply tools/call params._meta["toolstack/idempotency-key"] (1-128 letters/digits/_/-). Reuse only with the same action. Unknown outcomes are not retry permission.',
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self._list_tools()}
        if method == "tools/call":
            return self._call_tool(params)
        raise _MethodNotFound(method)

    def _list_tools(self) -> list:
        _, body = _call("GET", "/v1/tools")
        self._names = {}
        tools = []
        for t in body.get("tools", []):
            name = f"{t['tool']}__{t['op']}"
            self._names[name] = (t["tool"], t["op"])
            _, described = _call("GET", f"/v1/tools/{t['tool']}.{t['op']}")
            description = t.get("description", "")
            schema = _input_schema(described.get("args", []))
            if t.get("effect") == "review":
                description = (description + " (requires human approval)").strip()
                schema = _with_reason(schema)  # advertise the optional justification
            tools.append({"name": name, "description": description, "inputSchema": schema})
        return tools

    def _call_tool(self, params: dict) -> dict:
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        if name not in self._names:
            self._list_tools()  # refresh (client may call without a prior list)
        if name not in self._names:
            return _result(f'unknown tool "{name}"', is_error=True)
        tool, op = self._names[name]
        # `_reason` is adapter metadata, not a tool argument: pull it out (so it is
        # never forwarded to the tool) and pass it as the broker's justification,
        # the MCP equivalent of the CLI's --reason. It stays private to the broker
        # on review ops; audit records only whether metadata was provided.
        args = dict(arguments)
        reason = args.pop("_reason", None)
        body = {"arguments": args}
        if isinstance(reason, str) and reason.strip():
            body["reason"] = reason
        meta = params.get("_meta", {})
        if not isinstance(meta, dict):
            raise ValueError("_meta must be an object")
        key = meta.get("toolstack/idempotency-key")
        try:
            _, resp = _call("POST", f"/v1/actions/{tool}.{op}", body, idempotency_key=key) if key is not None else _call("POST", f"/v1/actions/{tool}.{op}", body)
        except (OSError, RuntimeError, HTTPException, json.JSONDecodeError) as exc:
            resp = {"status": "unknown", "error": "broker_transport_error", "detail": type(exc).__name__,
                    "source": "client", "note": "Use original key and exact payload; never auto-resubmit with a new key."}
        if resp.get("status") in _WAITING:
            resp = self._poll(resp["request_id"])
        if key is not None:
            resp.setdefault("idempotency_key", key)
        status = resp.get("status")
        nested = resp.get("result")
        is_error = (status in _FAIL or (status is None and "error" in resp)
                    or (isinstance(nested, dict) and nested.get("isError") is True))
        return _result(json.dumps(resp, indent=2), is_error=is_error)

    def _poll(self, request_id) -> dict:
        # On timeout, report status="timeout" (in _FAIL) so the tools/call result is
        # isError:true: the call has NOT completed, even though the request may still
        # be pending on the broker. Otherwise an MCP agent reads a timed-out call as a
        # successful one.
        if not math.isfinite(self._poll_timeout) or not 0 <= self._poll_timeout <= 86400:
            raise ValueError("invalid poll timeout")
        deadline = time.monotonic() + self._poll_timeout
        while True:
            try:
                _, resp = _call("GET", f"/v1/requests/{request_id}")
            except (OSError, RuntimeError, HTTPException, json.JSONDecodeError) as exc:
                return {"status": "unknown", "request_id": request_id, "source": "client",
                        "error": "broker_transport_error", "detail": type(exc).__name__}
            resp.setdefault("request_id", request_id)
            if resp.get("status") not in _WAITING:
                return resp
            if time.monotonic() >= deadline:
                return {**resp, "status": "timeout", "request_id": request_id,
                        "broker_status": resp.get("status"),
                        "note": (f"wait timed out after {self._poll_timeout:g}s; the "
                                  f"request is still {resp.get('status')} on the broker and "
                                 "has not completed")}
            time.sleep(min(2.0, max(0, deadline - time.monotonic())))


def _result(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _handle(server: Server, message: dict):
    mid = message.get("id")
    if mid is None:
        return None  # notification
    try:
        return {"jsonrpc": "2.0", "id": mid,
                "result": server.dispatch(message.get("method", ""), message.get("params") or {})}
    except _MethodNotFound as exc:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {exc}"}}
    except Exception as exc:  # surface as a JSON-RPC error, never crash the server
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": type(exc).__name__}}


def serve(stdin, stdout) -> None:
    server = Server()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(server, message)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


def main() -> None:
    serve(sys.stdin, sys.stdout)


if __name__ == "__main__":
    main()

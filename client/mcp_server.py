"""toolstack MCP server — exposes the broker's tools to an MCP-native agent.

A minimal stdio JSON-RPC (MCP) server: `tools/list` maps the caller's allowed broker
ops to MCP tools (with input schemas from the op's declared args), and `tools/call`
forwards to the broker, blocking on approval and returning the result (plus the
approver's note). The agent passes a structured `arguments` object — no shell, so no
quoting breakage. Run it as an MCP server command: `python3 -m client.mcp_server`.

Config (env): TOOLSTACK_URL, TOOLSTACK_TOKEN / TOOLSTACK_TOKEN_FILE (shared with the
CLI). Stdlib only.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error

from .toolstack import _FAIL, _send

PROTOCOL_VERSION = "2024-11-05"
_JSON_TYPES = {"string", "integer", "number", "boolean", "object", "array"}


def _call(method: str, path: str, body=None):
    # Same broker call as the CLI (client.toolstack._send); only the unreachable
    # case differs — surface it as a JSON-RPC error rather than exiting.
    try:
        return _send(method, path, body)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"broker unreachable: {exc.reason}")


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
            if t.get("effect") == "review":
                description = (description + " (requires human approval)").strip()
            tools.append({"name": name, "description": description,
                          "inputSchema": _input_schema(described.get("args", []))})
        return tools

    def _call_tool(self, params: dict) -> dict:
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        if name not in self._names:
            self._list_tools()  # refresh (client may call without a prior list)
        if name not in self._names:
            return _result(f'unknown tool "{name}"', is_error=True)
        tool, op = self._names[name]
        _, resp = _call("POST", f"/v1/actions/{tool}.{op}", {"arguments": arguments})
        if resp.get("status") == "pending_approval":
            resp = self._poll(resp["request_id"])
        status = resp.get("status")
        is_error = status in _FAIL or (status is None and "error" in resp)
        return _result(json.dumps(resp, indent=2), is_error=is_error)

    def _poll(self, request_id) -> dict:
        deadline = time.monotonic() + self._poll_timeout
        while True:
            _, resp = _call("GET", f"/v1/requests/{request_id}")
            if resp.get("status") != "pending_approval":
                return resp
            if time.monotonic() >= deadline:
                return {**resp, "note": "still pending (mcp wait timed out)"}
            time.sleep(2.0)


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
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(exc)}}


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

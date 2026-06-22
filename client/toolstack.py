#!/usr/bin/env python3
"""toolstack: the agent's generic client for calling tools through the broker.

Discover, describe, call, and wait on any tool the caller is allowed to use, in a
uniform, token-light way (schemas are fetched on demand, not carried in context):

    toolstack tools                          # what can I call? (allowed ops only)
    toolstack describe <tool>.<op>           # args for one op, on demand
    toolstack call <tool>.<op> '<json-args>' # run it (or get a pending request id)
    toolstack call <tool>.<op> '<json>' --reason "..." --wait
    toolstack wait <request_id>              # poll an approval to its outcome
    toolstack whoami

Config (env): TOOLSTACK_URL (default http://127.0.0.1:8765), and TOOLSTACK_TOKEN or
TOOLSTACK_TOKEN_FILE for the caller's bearer token. Stdlib only.

Exit code is non-zero on a denied/expired/failed/unavailable/timeout outcome or a
transport error, so an agent's shell can branch on success. A `--wait` that times
out client-side exits non-zero with `status: "timeout"` and the request id; the
approval is usually still live on the broker (its TTL outlasts the client wait), so
resume with `toolstack wait <id>`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8765"
# Outcomes the caller's shell should treat as failure (non-zero exit). "timeout" is
# a CLIENT-side outcome: the wait gave up, but the request may still be pending on
# the broker; it must NOT read as success.
_FAIL = {"denied", "expired", "failed", "unavailable", "invalid", "not_found",
         "rate_limited", "timeout"}


def _base() -> str:
    return os.environ.get("TOOLSTACK_URL", DEFAULT_URL).rstrip("/")


def _token() -> str | None:
    token = os.environ.get("TOOLSTACK_TOKEN")
    if token:
        return token
    path = os.environ.get("TOOLSTACK_TOKEN_FILE")
    if path:
        try:
            with open(os.path.expanduser(path), encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return None
    return None


def _send(method: str, path: str, body=None):
    """Send a request to the broker and return (status, parsed-json). Raises
    urllib.error.URLError if the broker is unreachable; callers decide how to
    surface that (the CLI exits; the MCP server returns a JSON-RPC error). Shared
    with client.mcp_server so the broker HTTP call lives in exactly one place."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(_base() + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_timeout()) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        finally:
            exc.close()


def _timeout() -> float:
    """Per-call broker timeout in seconds (default 30). Override with TOOLSTACK_CLIENT_TIMEOUT
    for slow tools or links."""
    try:
        return float(os.environ.get("TOOLSTACK_CLIENT_TIMEOUT", "30"))
    except ValueError:
        return 30.0


def _request(method: str, path: str, body=None):
    try:
        return _send(method, path, body)
    except urllib.error.URLError as exc:
        # Name the error class too: a timeout vs a refused connection vs DNS failure all arrive
        # as URLError subclasses, and the distinction matters when diagnosing.
        print(f"cannot reach broker at {_base()}: {type(exc).__name__}: {exc.reason}",
              file=sys.stderr)
        # The most common cause is "I installed the CLIs but never started a broker." Say so,
        # and point at the ways to start one (installing this package does not run anything).
        print("Is a broker running at that address? Start one from the admin app (Start broker), "
              "the Docker one-box (deploy/docker), the systemd service (deploy/), or directly with "
              "`python3 -m broker.server`. Point elsewhere with TOOLSTACK_URL.",
              file=sys.stderr)
        raise SystemExit(2)


def _print(obj) -> None:
    print(json.dumps(obj, indent=2))


def _finish(resp: dict) -> None:
    _print(resp)
    status = resp.get("status")
    if status in _FAIL or (status is None and "error" in resp):
        raise SystemExit(1)


def _poll_until_done(request_id: int, timeout: float, interval: float = 2.0) -> dict:
    """Poll a pending request to a terminal outcome, or to a client-side timeout.

    On timeout the outcome is reported as `status: "timeout"` (a failure; see _FAIL),
    NOT the broker's `pending_approval`: the call has not completed, so it must not read
    as success. The request usually outlives this wait (the broker's approval TTL is far
    longer than the default client timeout), so the result carries the request id to
    resume with `toolstack wait <id>`."""
    deadline = time.monotonic() + timeout
    while True:
        _, resp = _request("GET", f"/v1/requests/{request_id}")
        if resp.get("status") != "pending_approval":
            return resp
        if time.monotonic() >= deadline:
            return {**resp, "status": "timeout", "request_id": request_id,
                    "note": (f"client wait timed out after {timeout:g}s; the request is "
                             f"still pending on the broker. Resume with "
                             f"`toolstack wait {request_id}`")}
        time.sleep(interval)


def cmd_tools(args) -> None:
    status, body = _request("GET", "/v1/tools")
    if status != 200:
        return _finish(body)
    for t in body.get("tools", []):
        print(f"{t['tool']}.{t['op']}\t{t['effect']}\t{t['risk']}\t{t.get('description', '')}")


def cmd_describe(args) -> None:
    _finish(_request("GET", f"/v1/tools/{args.spec}")[1])


def _load_arguments(args) -> dict:
    """Resolve the JSON arguments object from the first source present, in order:
    --args-file, then an inline positional, then piped stdin (e.g. a heredoc). An
    explicit inline arg deliberately beats ambient stdin, so a redirected or empty
    stdin can't silently override it. Prefer --args-file or a quoted heredoc for
    values with quotes, newlines, `$`, or backticks; they avoid shell-quoting
    breakage that a hand-built inline JSON string is prone to."""
    if args.args_file:
        try:
            with open(os.path.expanduser(args.args_file), encoding="utf-8") as f:
                raw = f.read()
        except OSError as exc:
            print(f"cannot read --args-file: {exc}", file=sys.stderr)
            raise SystemExit(2)
    elif args.args is not None:
        raw = args.args
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()  # piped data / heredoc
    else:
        raw = ""
    raw = raw.strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        print("arguments must be valid JSON (an object)", file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(value, dict):
        print("arguments must be a JSON object", file=sys.stderr)
        raise SystemExit(2)
    return value


def cmd_call(args) -> None:
    body = {"arguments": _load_arguments(args)}
    if args.reason:
        body["reason"] = args.reason
    _, resp = _request("POST", f"/v1/actions/{args.spec}", body)
    if args.wait and resp.get("status") == "pending_approval":
        resp = _poll_until_done(resp["request_id"], args.timeout)
    _finish(resp)


def cmd_wait(args) -> None:
    _finish(_poll_until_done(args.request_id, args.timeout))


def cmd_whoami(args) -> None:
    status, body = _request("GET", "/v1/tools")
    if status != 200:
        return _finish(body)
    print(f"caller: {body.get('caller')}  ({len(body.get('tools', []))} ops allowed)")


def main() -> None:
    parser = argparse.ArgumentParser(prog="toolstack")
    sub = parser.add_subparsers(required=True)
    sub.add_parser("tools", help="list the ops this caller may use").set_defaults(func=cmd_tools)
    sub.add_parser("whoami", help="show the caller").set_defaults(func=cmd_whoami)

    d = sub.add_parser("describe", help="show one op's args")
    d.add_argument("spec", metavar="TOOL.OP")
    d.set_defaults(func=cmd_describe)

    c = sub.add_parser("call", help="call a tool operation")
    c.add_argument("spec", metavar="TOOL.OP")
    c.add_argument("args", nargs="?", default=None,
                   help="JSON arguments object (prefer stdin/heredoc or --args-file)")
    c.add_argument("--args-file", help="read JSON arguments from a file (shell-safe)")
    c.add_argument("--reason", help="justification (use only for review ops / retries)")
    c.add_argument("--wait", action="store_true", help="poll to the outcome if review-required")
    c.add_argument("--timeout", type=float, default=300, metavar="SECONDS",
                   help="client-side wait for approval (default 300); on timeout, exits "
                        "non-zero with status=timeout and the request id to resume")
    c.set_defaults(func=cmd_call)

    w = sub.add_parser("wait", help="poll a pending request to its outcome")
    w.add_argument("request_id", type=int)
    w.add_argument("--timeout", type=float, default=300, metavar="SECONDS",
                   help="client-side wait (default 300); on timeout, exits non-zero "
                        "with status=timeout. Re-run `toolstack wait <id>` to keep waiting")
    w.set_defaults(func=cmd_wait)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

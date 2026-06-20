# Agent client

The generic shim an agent uses to call tools through the broker: one CLI for all
tools, with **lazy discovery** (schemas fetched on demand, not carried in context).
Stdlib Python, zero dependencies.

- [SKILL.md](SKILL.md): the agent-facing skill (workflow + the comment/reason strategy).
- [toolstack.py](toolstack.py): the CLI.

## Use it

```bash
export TOOLSTACK_URL=http://127.0.0.1:8765
export TOOLSTACK_TOKEN=<caller token>     # or TOOLSTACK_TOKEN_FILE=<path>

python3 -m client.toolstack tools                      # ops this caller may use
python3 -m client.toolstack describe echo.say          # args, on demand
python3 -m client.toolstack whoami

# arguments are passed shell-safely: heredoc (default), --args-file, or inline JSON
python3 -m client.toolstack call echo.say <<'JSON'
{"m": "any 'quotes', \"quotes\", $vars, multi-line, no escaping"}
JSON
python3 -m client.toolstack call echo.say --args-file args.json
python3 -m client.toolstack call echo.say '{"m":"hi"}'        # trivial args only

python3 -m client.toolstack call echo.secret_status '{}' --reason "why" --wait  # if policy marks it review
python3 -m client.toolstack wait <request_id>          # poll; surfaces the approver's note
```

Passing arguments via stdin/heredoc or `--args-file` (rather than a quoted CLI
argument) avoids shell-quoting breakage on quotes, newlines, `$`, etc.; the data
rides in the body, like an HTTP POST.

Exit code is non-zero on a denied/expired/failed/unavailable outcome, so a shell can
branch on success.

## Shape

**Hybrid:** this generic client is the default for every tool. A tool may also ship
an optional per-domain skill with richer workflows where it earns its keep; it still
calls the broker through this same client underneath.

## MCP server (no shell at all)

For MCP-native agent runtimes, [mcp_server.py](mcp_server.py) exposes the same tools
over MCP (stdio JSON-RPC): `tools/list` maps the caller's allowed ops (with input
schemas from each op's args), and `tools/call` forwards to the broker, blocking on
approval and returning the result plus the approver's note. The agent passes a
structured `arguments` object, so there is **no shell and no quoting risk**: the
most robust path for varied input.

Run it as the MCP server command (same `TOOLSTACK_URL` / `TOOLSTACK_TOKEN` env):

```bash
python3 -m client.mcp_server
```

## Test it

```bash
python3 -m unittest discover -s client/tests -t .
```

The test drives the CLI against a real in-process broker (fake runtime + fake
approval surface), covering discovery, an allowed call, and the review → wait →
approver-note round-trip.

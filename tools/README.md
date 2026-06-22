# Tools

Example tools and the template for writing your own. A tool is its own standalone program;
the toolyard runs it on a loopback port and the broker forwards approved calls to it.

## Choosing a transport (`type`)

Every tool declares one of three transports in its `toolyard.toml`. The broker dispatches on
it ([../broker/runtime.py](../broker/runtime.py)); policy, approval, and audit work identically
across all three; ops are always the unit of policy (`<tool>.<op>`).

| `type` | The tool is... | The broker... | Example |
|---|---|---|---|
| `api`  | an HTTP service answering `POST /v1/actions/<op>` | POSTs the op + arguments, returns the tool's JSON | [echo_api/](echo_api/) |
| `mcp`  | a streamable-HTTP **MCP server** at `/mcp` | is the MCP **client**: runs `initialize`, then `tools/call` with the op as the tool name | [echo_mcp/](echo_mcp/) |
| `rest` | any HTTP service (a passthrough) | forwards the raw `<verb> <path>` request; the op IS the HTTP verb, risk derives from it, and the caller's policy can scope it per path | [rest_kv/](rest_kv/) |

- Pick **api** for a normal action-style tool (one op per capability).
- Pick **mcp** to put an existing MCP server behind the broker's policy/approval.
- Pick **rest** to proxy a REST API: the caller passes `{path, body, query, headers}` and gets
  back `{status, headers, body}`, gated per `(verb, path)` in policy (e.g. `kv.GET /items/**`).
  To put an **external authenticated API** (MS Graph, etc.) behind the broker with **no tool
  code**, point a rest tool's `command` at the bundled `python3 -m toolyard.http_proxy` and add a
  `[proxy]` block (a `base_url` plus a secret-to-request `inject` map). The proxy injects your
  credential and forwards under `base_url`; the broker never sees the secret. See
  [../toolyard/http_proxy.py](../toolyard/http_proxy.py).

All three are served on a loopback port the toolyard assigns; see
[../toolyard/README.md](../toolyard/README.md) for the manifest, runners, and secrets.

## The examples

- **[echo_api/](echo_api/)**, `type = "api"`, the tool template: serves `/v1/actions/<op>`,
  reads its own secret from `$TOOLSTACK_SECRETS_DIR`, with an optional broker shared-secret check.
- **[echo_mcp/](echo_mcp/)**, `type = "mcp"`, the same echo exposed as a streamable-HTTP MCP server.
- **[rest_kv/](rest_kv/)**, `type = "rest"`, a small REST CRUD key-value store behind the
  verb-as-op passthrough.

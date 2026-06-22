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
| `rest` | any HTTP service | a **named op** maps to a `(verb, path-template)`; the broker fills the template from the caller's params and forwards `<verb> <path>`. A bare verb (no `path`) is the passthrough escape hatch: the op IS the verb and policy scopes the caller's path by glob. Risk derives from the verb. | [rest_kv/](rest_kv/) |

- Pick **api** for a normal action-style tool (one op per capability).
- Pick **mcp** to put an existing MCP server behind the broker's policy/approval.
- Pick **rest** to put a REST API behind the broker. Prefer **named ops**: declare each capability
  as a `(name, verb, path)`, and the caller invokes it by name and fills the path's `{params}`. It
  never constructs a free path, and policy grants by name (`graph.get_task`) exactly like an api or
  mcp op:

      [[operations]]
      name = "get_task"
      verb = "GET"
      path = "/me/todo/lists/{list_id}/tasks/{task_id}"   # the caller fills {list_id}, {task_id}

  `{name}` is one path segment (a `/`, `.` or `..` in the value is refused); `{+name}` is an explicit
  cross-segment tail (use it sparingly: it grants the whole subtree under the prefix). The bare-verb
  form (an op named `GET` with no `path`) stays as an escape hatch: the caller passes
  `{path, query, body, headers}`, gets back `{status, headers, body}`, and policy scopes the path by
  glob (`kv.GET /items/**`). That is handy for a broad read grant but looser than a named op.

  To front an **external authenticated API** (MS Graph, etc.) with **no tool code**, point the
  tool's `command` at the bundled `python3 -m toolyard.http_proxy` and add a `[proxy]` block
  (`base_url` plus a secret-to-request `inject` map); the proxy injects your credential and pins
  every route under `base_url`, and the broker never sees the secret. Generate the whole
  `toolyard.toml` from a spec with `python3 -m toolyard.openapi_import <spec> --id <tool> --port
  <port>` (operationId becomes the op name, method the verb, path the template). See
  [../toolyard/http_proxy.py](../toolyard/http_proxy.py).

All three are served on a loopback port the toolyard assigns; see
[../toolyard/README.md](../toolyard/README.md) for the manifest, runners, and secrets.

## The examples

- **[echo_api/](echo_api/)**, `type = "api"`, the tool template: serves `/v1/actions/<op>`,
  reads its own secret from `$TOOLSTACK_SECRETS_DIR`, with an optional broker shared-secret check.
- **[echo_mcp/](echo_mcp/)**, `type = "mcp"`, the same echo exposed as a streamable-HTTP MCP server.
- **[rest_kv/](rest_kv/)**, `type = "rest"`, a small REST CRUD key-value store. Shows both forms
  on one service: the verb-as-op passthrough (`GET`/`POST`/...) and named ops (`get_item`,
  `delete_item`) that pin a `(verb, path)` and are granted by name.

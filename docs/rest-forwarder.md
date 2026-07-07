# REST Forwarder

`type = "rest"` tools are named HTTP operations backed by the generic
`toolstack_forwarder` process. Each REST tool is still one toolyard-managed
process with one secrets directory and one loopback port.

## Manifest Shape

```toml
id = "jira"
type = "rest"
base_url = "https://api.example.test"

[entrypoint]
command = "python3 -m toolstack_forwarder"
port = 4621

[[operations]]
name = "get_user"
risk = "read"
verb = "GET"
path = "/users/{user_id}"
allowed_headers = ["X-Trace"]
body_kind = "none"

args = [
  { name = "variables", type = "object", required = true, description = "Path variables: user_id" },
  { name = "headers", type = "object", required = false, description = "Allowed headers: X-Trace" },
]
```

`path` supports single-segment `{name}` variables in the path and query text, for
example `/users?email={email}`. Path variable values are stripped, bounded,
validated as printable ASCII, rejected for `/`, `.`, whitespace, and encoded
forbidden forms, then percent-encoded before insertion. Query variable values use
the same printable-ASCII bound but allow query-safe content before percent-encoding.

`body_kind` is `none`, `text`, or `binary`. Text bodies are UTF-8 strings and may
substitute `{{secret:NAME}}`; binary bodies are base64 and force substitution off.
`TOOLSTACK_REST_BODY_MAX` caps outbound body bytes and upstream response bytes.

Discovery should describe the broker envelope: `variables` for path template
values, `headers` for the allowlisted outbound headers, and `body` when
`body_kind` is not `none`.

## OpenAPI Import

Toolyard can scaffold the manifest from an OpenAPI/Swagger JSON file:

```bash
python3 -m toolyard.openapi_import openapi.json --id jira --port 4621 > tools/jira/toolyard.toml
```

The importer generates named operations for path templates and header auth
scaffolding. The admin panel exposes the same parser and accepts YAML when its
optional PyYAML dependency is installed.

## Broker Wire

The broker calls the forwarder:

```json
{
  "op": "get_user",
  "arguments": {"variables": {"user_id": "u42"}, "headers": {}, "body": "{}"},
  "broker_request_id": 123,
  "caller": {"name": "hermes"}
}
```

`X-Toolstack-Secret` is optional and works the same way as api / mcp tools. If the
broker has a shared secret for the tool it sends the header; if the forwarder has
`$TOOLSTACK_SECRETS_DIR/broker_secret`, it verifies the header. With neither side
configured, the channel check stays off.

Success:

```json
{"status": 200, "headers": {"content-type": "application/json"}, "body": "{\"ok\":true}"}
```

Failure:

```json
{"error": "missing_variable", "name": "user_id"}
```

The forwarder never follows redirects, strips `Set-Cookie` and hop-by-hop
headers from result envelopes, and returns upstream 3xx/4xx/5xx as data.

## Secret Update Rules

Operations can extract values from successful responses and write writable
secrets through the existing toolyard write-proxy:

```toml
secret_update_rules = [
  { secret_name = "auth_token", response_type = "json", extract_path = "session.token", match_status = "200|201" },
]
```

Supported `response_type`: `json`, `xml`, `form`, `plaintext`.
Extraction is all-or-nothing before writes begin. A write failure after a prior
write is logged with SHA-256 fingerprints only, never secret values.

## Broker Visibility

The broker registry stores only REST metadata needed for routing, audit, and
approval cards: op name, risk, port, verb, host, path template, and body kind.
It never reads `[[secrets]]` and never stores `base_url` path/query text.

REST ops are not exposed through broker-native `/mcp`.

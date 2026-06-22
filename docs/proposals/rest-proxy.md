# Proposal: a generic REST proxy tool

Turn an external HTTP API into a Toolstack `rest` tool by **configuration alone**, with no tool
code to write. The bundled proxy injects the credential and pins every route under one host;
named operations (see below) keep the caller to the routes you declared and grant them by name.

## The idea

Today a `rest` tool is a real HTTP service the broker forwards `<verb> <path>` to. To put MS
Graph behind Toolstack you'd write a proxy process that reads its token and forwards to
`graph.microsoft.com`. Instead, ship that proxy once as a reusable **entrypoint wrapper** and
let operators point a tool's `command` at it:

```toml
id = "graph"
type = "rest"
[entrypoint]
command = "python3 -m toolyard.http_proxy"   # the bundled wrapper; you write no code
port = 4640
[proxy]
base_url = "https://graph.microsoft.com/v1.0"
inject = [
    { into = "header", name = "Authorization", value = "Bearer ${secret:graph_token}" },
    # also: { into = "query", ... } / { into = "body", ... }
]
[[operations]]            # NAMED ops: the caller invokes by name + fills {params}; policy grants by name
name = "list_messages"
verb = "GET"
path = "/me/messages"
[[operations]]
name = "get_message"
verb = "GET"
path = "/me/messages/{id}"
[[secrets]]
name = "graph_token"
field = "GRAPH_TOKEN"     # resolved from your backend into THIS process, never the broker
```

`graph.get_message {id = "AAMk..."}` -> proxy -> `GET .../v1.0/me/messages/AAMk...` with the bearer header.

The broker reads only `id` / `type` / `operations` / `port` and ignores the `[proxy]` block (as
it already ignores `[[secrets]]`); only the wrapper reads it. So this is **zero framework
change** - the wrapper is an ordinary `rest` tool.

## Named operations

A rest op is a named `(verb, path-template)`: the caller invokes it by **name** and fills the
template's `{params}`, so it never constructs a free path, and policy grants by name
(`graph.get_message`) exactly like an api / mcp op. This is what keeps a wandering bot on the
rails: it can only reach the routes you declared, and a route you didn't declare is simply not an
op it can call.

- `{name}` is exactly ONE path segment: the broker percent-encodes the value, and a `/`, `.` or
  `..` in it is refused, so a param can't add path structure or traverse.
- `{+name}` is an explicit cross-segment tail (RFC 6570 reserved expansion) for when an op really
  does front a subtree. Use it sparingly: because policy grants the op by name, a `{+name}` op
  confers the whole subtree under its prefix. Prefer enumerating `{name}` routes.
- The path template uses the same `{param}` spelling as OpenAPI / Swagger, so a spec maps 1:1.
  `python3 -m toolyard.openapi_import <spec> --id graph --port 4640 > graph/toolyard.toml`
  generates the named ops (operationId -> name, method -> verb, path -> template) plus a base_url
  and an auth scaffold. Point it at a documented API and you get a policy-gated tool.
- The **bare-verb passthrough** (an op named `GET` with no `path`) stays as an escape hatch: the
  caller supplies `{path, query, body, headers}` and policy scopes the path by glob
  (`kv.GET /items/**`). Looser than a named op; reach for it only for a deliberately broad grant.

For a `review`-gated op the approval card shows the resolved path **and** the query, so the human
approves the exact request that runs, not a narrower-looking path.

## Security spine

- **Secrets stay off the broker.** The toolyard resolves them into the wrapper's secrets dir;
  the broker only ever talks to loopback and never sees them. The credential goes out in the
  upstream request and is never returned, logged, or echoed to the caller. This is *why* it's a
  tool, not broker-side injection: putting the broker on the secret path would break the core
  invariant and hand it an SSRF egress surface.
- **base_url pinning (no SSRF).** Every request is pinned to `base_url`'s scheme + host; the
  caller's path is normalised and must stay under `base_url`'s path prefix, so `..`, a host
  swap, or a protocol-relative authority can't redirect it. Rejected before any upstream call. A
  `${secret:...}` ref may fill a segment of base_url's PATH (e.g. a secret account id in the
  prefix) but never the host, so the request stays pinned to one origin.
- **The injected auth is not caller-overridable.** By default caller headers are **not** forwarded
  upstream; only the configured injections (plus `Content-Type` for a JSON body) go out. An
  operator can allowlist specific per-call app headers with `forward_headers = ["If-Match",
  "Prefer", ...]`; the auth, broker, and transport/framing headers can never be on that list, and
  a value carrying a CRLF / obs-fold is refused, so neither the credential nor the request framing
  is caller-overridable.
- **Defense in depth.** Like the other templates, if a `broker_secret` is provisioned the
  wrapper requires the broker's `X-Toolstack-Secret`, so a stray loopback process can't use the
  proxy (and its live credentials) behind the broker's back. Strongly recommended here.
- **Policy still gates everything.** The per-(verb, path) rules decide allow / review / deny
  before the broker forwards, so you scope exactly which paths the bot may hit and route writes
  through human approval. Unchanged.
- **Egress is isolatable.** Because the workload (not the broker) makes the outbound call, you
  can network-restrict that one tool without loosening the broker.

## Token rotation (provider-agnostic)

Tokens expire. The proxy re-reads the injected secret on every request, so the only missing
piece is a way to put a fresh token in place without redeploying. That's an opt-in control op:

```toml
[proxy]
base_url = "https://graph.microsoft.com/v1.0"
rotatable = ["graph_token"]          # writable secrets the control plane may set
inject = [{ into = "header", name = "Authorization", value = "Bearer ${secret:graph_token}" }]
[[secrets]]
name = "graph_token"
writable = true                      # so the toolyard spawns the writable-secret proxy
```

```
PUT /.toolstack/secret/graph_token  {"value": "<fresh token>"}  ->  {"ok": true, "rotated": "graph_token"}
```

**This is not OAuth-specific.** The proxy does no re-auth itself: whoever obtained the new token
(by any scheme - an OAuth2 refresh, a device-code flow, an internal STS, or a human pasting a new
PAT) hands the resulting token to the control op, and the next upstream call uses it. The proxy
stores whatever string it's given; it has no idea what flow produced it. An OAuth client *can*
sit in front of this, but nothing here assumes one.

The write path reuses the writable-secret proxy we already ship: the op forwards the value to the
toolyard's local Unix socket (`$TOOLYARD_SECRETS_SOCKET`), which patches the backend. The broker
is never on this path, and the gates stack:

- **Off by default.** The op doesn't exist unless `rotatable` is non-empty.
- **Policy-gated.** It's a `PUT` on `control_prefix` (default `/.toolstack/secret`), so the
  caller needs a policy grant for that verb+path like any other write; route it through approval
  if you want a human in the loop on every rotation. Author the grant against the exact control
  path rather than a broad `PUT /.toolstack/**` (under most-specific-wins a broad allow can
  out-rank a less-literal deny).
- **Double-gated.** The name must be in `rotatable` *and* the write-proxy independently re-checks
  the secret is declared `writable`, so neither config alone is enough.
- **Never echoes the value.** The response is `{ok, rotated}`; the token is not returned, logged,
  or reflected.

## Status

- **v1 built:** `toolyard/http_proxy.py` - base_url + header/query/body injection, base-pinning,
  caller-header drop, broker-secret check, fail-closed on a missing secret.
- **Phase 2 built: token rotation** (above) - the provider-agnostic `PUT control_prefix/<name>`
  write-back over the existing writable-secret proxy, gated by `rotatable` + policy + the
  write-proxy's own writability check, value never echoed.
- **Also built: `forward_headers` + base_url path secrets.** An operator can allowlist specific
  per-call caller headers (the auth/broker/framing headers stay un-forwardable, CRLF values
  refused), and a `${secret:...}` ref can fill a base_url path segment (host stays fixed; an
  empty/misprovisioned secret fails closed rather than widening scope).
- **Named operations built (broker).** A rest op may be a named `(verb, path-template)`; the
  broker fills the template (`broker/runtime.resolve_rest_path`), keys policy on the op name, and
  shows the resolved path + query on the approval card. `{name}` is one encoded segment (no
  traversal), `{+name}` an explicit tail. Tested across registry / runtime / lifecycle; an
  adversarial pass confirmed the segment, traversal, method-injection, and default-deny invariants.
- **OpenAPI importer built:** `toolyard/openapi_import.py` (`python3 -m toolyard.openapi_import`)
  turns a spec into a named-op `toolyard.toml`; tested with a round-trip back through the registry.
- Tested (`toolyard/tests/test_http_proxy.py`): pinning + escape rejection, secret injection, an
  end-to-end run through a real proxy against a fake upstream, the rotation path end to end
  against the real write-proxy (writes the secret, refuses non-rotatable names, requires `PUT`,
  never forwards the control request upstream), header-allowlist forwarding + the obs-fold refusal,
  and base_url path-secret substitution + its fail-closed.
- **Deferred: docker runner.** v1 targets the process runner (the wrapper reads `./toolyard.toml`
  and the toolyard package is on PATH). A docker image would need the package + config baked in;
  a small base image can follow.

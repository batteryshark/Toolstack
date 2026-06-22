# Proposal: a generic REST proxy tool

Turn an external HTTP API into a Toolstack `rest` tool by **configuration alone**, with no tool
code to write, and without changing the broker, the toolyard, or the tool model.

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
[[operations]]            # the verbs you allow; policy scopes them per (verb, path)
name = "GET"
[[secrets]]
name = "graph_token"
field = "GRAPH_TOKEN"     # resolved from your backend into THIS process, never the broker
```

`graph.GET {path = "/me/messages"}` -> proxy -> `GET .../v1.0/me/messages` with the bearer header.

The broker reads only `id` / `type` / `operations` / `port` and ignores the `[proxy]` block (as
it already ignores `[[secrets]]`); only the wrapper reads it. So this is **zero framework
change** - the wrapper is an ordinary `rest` tool.

## Security spine

- **Secrets stay off the broker.** The toolyard resolves them into the wrapper's secrets dir;
  the broker only ever talks to loopback and never sees them. The credential goes out in the
  upstream request and is never returned, logged, or echoed to the caller. This is *why* it's a
  tool, not broker-side injection: putting the broker on the secret path would break the core
  invariant and hand it an SSRF egress surface.
- **base_url pinning (no SSRF).** Every request is pinned to `base_url`'s scheme + host; the
  caller's path is normalised and must stay under `base_url`'s path prefix, so `..`, a host
  swap, or a protocol-relative authority can't redirect it. Rejected before any upstream call.
- **The injected auth is not caller-overridable.** Caller-supplied headers are **not** forwarded
  upstream; only the configured injections (plus `Content-Type` for a JSON body) go out.
- **Defense in depth.** Like the other templates, if a `broker_secret` is provisioned the
  wrapper requires the broker's `X-Toolstack-Secret`, so a stray loopback process can't use the
  proxy (and its live credentials) behind the broker's back. Strongly recommended here.
- **Policy still gates everything.** The per-(verb, path) rules decide allow / review / deny
  before the broker forwards, so you scope exactly which paths the bot may hit and route writes
  through human approval. Unchanged.
- **Egress is isolatable.** Because the workload (not the broker) makes the outbound call, you
  can network-restrict that one tool without loosening the broker.

## Status

- **v1 built:** `toolyard/http_proxy.py` - base_url + header/query/body injection, base-pinning,
  caller-header drop, broker-secret check, fail-closed on a missing secret. Tested
  (`toolyard/tests/test_http_proxy.py`): pinning + escape rejection, secret injection, and an
  end-to-end run through a real proxy against a fake upstream.
- **Deferred (phase 2): token reup.** The refresh token is a *writable* secret; on a 401 the
  wrapper can re-auth at the provider's token endpoint and write the rotated tokens back through
  the existing writable-secret proxy - entirely in the workload, broker never involved. It's
  OAuth2-provider-specific, so it ships as an optional `[proxy.refresh]` block after v1.
- **Deferred: docker runner.** v1 targets the process runner (the wrapper reads `./toolyard.toml`
  and the toolyard package is on PATH). A docker image would need the package + config baked in;
  a small base image can follow.

# Broker

The authority boundary: the only address an agent can reach. See [../plan.md](../plan.md) and
[../toolyard/README.md](../toolyard/README.md) for running tools, and
[../client/SKILL.md](../client/SKILL.md) for how an agent calls in.

## What works now

- Binds **`127.0.0.1` only** (host not configurable; the boundary depends on it).
- **`GET /v1/health`**: the only unauthenticated route.
- **`POST /v1/actions/<tool>.<op>`**: authenticated with `Authorization: Bearer <token>`:
  - `200` ran · `202` review-required (opened in nod) · `403` denied · `404` unknown
    · `400` malformed · `429` rate-limited · `502` tool failed/unreachable · `503` approval
    surface unavailable.
- **`GET /v1/requests/<id>`**, poll a request (owner only): drives approval
  resolution and returns the current status (`pending_approval` → `ok` / `denied` /
  `expired`), the tool `result` once it completes, and the `approver` + `note` for a
  reviewed request (the human's decision reason, surfaced back to the agent).
- **`GET /v1/tools`** / **`GET /v1/tools/<tool>.<op>`**, discovery: the ops this
  caller may use (filtered by policy, with effect/risk/description), and one op's
  args on demand. Lets agents discover lazily instead of carrying schemas in context.
- **`POST /mcp`**, broker-native **MCP** (JSON-RPC, streamable HTTP): the same tools, auth,
  policy, approval, and audit as the HTTP action API, for agents that speak MCP. A `tools/call`
  maps to the same lifecycle as `POST /v1/actions`; resolution is poll-only (`tools/call`
  returns a request id to poll, same as a `202` action response).
- **Identity**: callers + bearer tokens stored as SHA-256 hashes; revoking a token
  or caller takes effect on the next request.
- **Policy**: per-caller `allow` / `review` / `deny`, **default-deny**.
- **Registry**: reads tool/op/`type`/risk/port from `toolyard.toml` files under
  `TOOLSTACK_TOOLS_ROOT`, and **never parses the `[[secrets]]` block** (the broker
  stays secret-unaware).
- **Request lifecycle**: registry lookup → policy → **forward to the tool** on
  `127.0.0.1:<port>` (adding `broker_request_id` + caller name, never secrets),
  with persisted request state and an append-only **audit log in SQLite**.
- **Approval**: a `review` operation opens a nod decision via the `NodSurface`
  adapter and parks the request; the broker executes only on a **confirmed
  approval**, denies on rejection, and **fails closed on its own timeout** (poll is
  truth; the broker owns approval truth). The agent retrieves the result by polling
  `GET /v1/requests/<id>`. Arguments are kept only while pending, then cleared, and
  are never audited.
- **Hardening**: per-caller rate limiting (`429` over the limit); operator changes
  and a caller's optional `reason` are recorded in audit, with `reason` redacted.

Not implemented by design: the approval `deliver` callback fast-path. Resolution is
poll-only; a nod callback receiver is rejected because nod posts callbacks
unauthenticated (anyone reaching it could forge an approval).

Deferred (deployment hardening): container **tmpfs** secret injection, temporary
grants, and component credentials/mTLS (only if modules split across hosts).

## Run it

For an end-to-end run (start a tool, then the broker), see
[../toolyard/README.md](../toolyard/README.md). In short, from the repo root:

```bash
# 1. start a tool (toolyard resolves its secrets and runs it)
cp secrets.example.toml secrets.toml
python3 -m toolyard.cli up echo --secrets secrets.toml

# 2. create a caller, then start the broker pointed at the tools root
python3 -m broker.brokerctl create-caller --name hermes --allow echo.say
TOOLSTACK_TOOLS_ROOT=tools python3 -m broker.server

# 3. call it
TOKEN=<token from step 2>
curl -s -X POST http://127.0.0.1:8765/v1/actions/echo.say \
     -H "Authorization: Bearer $TOKEN" -d '{"arguments": {"m": "hi"}}'
# -> {"status":"ok","request_id":1,"result":{"echoed":{"m":"hi"}}}
# (a 502 {"error":"tool_unreachable"} here means the tool isn't running: start it with step 1)
```

Configuration (env vars):

- `TOOLSTACK_BROKER_PORT`: listen port (default `8765`).
- `TOOLSTACK_BROKER_DB`: database path (default
  `${XDG_STATE_HOME:-~/.local/state}/toolstack/broker/broker.sqlite3`).
- `TOOLSTACK_TOOLS_ROOT`: directory of `<tool>/toolyard.toml` files for the
  registry (unset = empty registry, every action `404`s).
- `TOOLSTACK_NOD_URL` + `TOOLSTACK_NOD_TOKEN`: nod base URL and issuer token for
  the approval surface (unset = no surface; `review` ops return `503`).
- `TOOLSTACK_APPROVAL_TTL`: broker-side approval timeout in seconds (default `3600`).
- `TOOLSTACK_RATE_LIMIT`: action submissions per caller per minute (default `120`; `0` = off).

## Operator (brokerctl)

The operator runs `brokerctl` on the broker host (direct SQLite: no networked admin
surface to secure). Mutating actions are recorded as `admin.*` audit events.

```bash
python3 -m broker.brokerctl create-caller --name hermes --allow echo.say --review echo.skip
python3 -m broker.brokerctl list-callers
python3 -m broker.brokerctl set-policy --name hermes --allow echo.say
python3 -m broker.brokerctl show-policy --name hermes
python3 -m broker.brokerctl revoke-token --prefix <hash-prefix>   # see list-tokens
python3 -m broker.brokerctl revoke-caller --name hermes
python3 -m broker.brokerctl list-requests --status pending_approval
python3 -m broker.brokerctl audit --request-id <N>   # answers the four audit questions
```

## Test it

Standard-library `unittest`, no dependencies. From the repo root:

```bash
python3 -m unittest discover -s broker/tests -t .
```

(`pytest broker` also works.)

## Module seams

One process, internal modules (not separate services):

- `gateway.py`: ingress/egress, routing, correlation ids, body validation.
- `identity.py`: callers + hashed bearer tokens; fail-closed `authenticate`.
- `policy.py`: `allow` / `review` / `deny`, default-deny (pure).
- `registry.py`: reads `toolyard.toml` for tool/op/risk/port; ignores `[[secrets]]`.
- `runtime.py`, forwards an approved call to the tool on `127.0.0.1:<port>`, dispatching the
  tool's transport: `api` (POST /v1/actions/<op>) or `mcp` (broker is the MCP *client*).
- `request_lifecycle.py`: the orchestration across the above (incl. approval resolution).
- `approval.py`: the operation card + normalized surface state (the adapter contract).
- `mcp.py`, the **`POST /mcp` ingress**: the broker as an MCP *server*, terminating JSON-RPC
  and re-entering the same lifecycle. (Two MCP roles: this serves agents; `runtime.py` calls
  an mcp *tool*.)
- `surface_nod.py`, `NodSurface`: the HTTP adapter to nod (open / poll / cancel).
- `store.py`: SQLite persistence (callers, tokens, policies, requests, approvals, audit).
- `audit.py`: append-only audit log; the server adds a stderr sink.
- `server.py`: the thin HTTP transport; binds localhost.
- `brokerctl.py`: operator CLI (callers, policies, tokens, requests, audit).
- `redaction.py`: bound + mask free-text before it enters audit.
- `ratelimit.py`: per-caller fixed-window rate limiter.

## The tailnet step (operational, not code)

External agents never hit the broker directly. Put it behind a tailnet and let
Tailscale Serve terminate TLS and proxy to localhost:

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8765
```

The agent then reaches `https://broker.<tailnet>.ts.net`; nothing off the tailnet
can reach the broker at all.

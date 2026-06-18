# Boundary Contracts

Under the [collapsed architecture](component-decomposition.md), most former
inter-service messages are now **in-process calls between broker modules** and need
no wire contract. This doc covers only the messages that cross a **process or trust
boundary**, plus the shared vocabulary and the rules every boundary obeys.

The approval boundary (broker ↔ nod) has its own spec:
[approval-surface-adapter.md](approval-surface-adapter.md).

## Standard outcomes

| Outcome | Meaning |
|---|---|
| `ok` | Completed successfully. |
| `accepted` | Accepted for later processing. |
| `pending_approval` | Paused until approval resolves. |
| `denied` | Policy, token, or approval refused it. |
| `invalid` | Malformed or semantically invalid. |
| `not_found` | Referenced resource does not exist. |
| `expired` | Request, approval, token, or grant expired. |
| `unavailable` | A dependency or external surface is down. |
| `failed` | Attempted and failed. |

## The boundaries

### 1. Agent → Broker (the only ingress)

```text
GET  /v1/health                  open; liveness only
GET  /v1/tools                   discovery: this caller's allowed ops (effect/risk/description)
GET  /v1/tools/<tool>.<op>       discovery: one op's args, on demand
POST /v1/actions/<tool>.<op>     Body: {"arguments": {...}, "reason": "<optional>"}
GET  /v1/requests/<id>           poll a request (owner only) -> status + result + approver/note
```

- Auth: `Authorization: Bearer <token>` (one caller). Only `GET /v1/health` is open.
- Action responses: `200` ran · `202` pending review · `403` denied · `404` unknown ·
  `400` invalid · `429` rate-limited · `502` tool failed · `503` approval surface unavailable.
- A reviewed request resolves on poll to `ok` / `denied` / `expired`, carrying the
  human's `approver` + `note`; the agent's (redacted) `reason` is shown to the approver.
- Discovery is policy-filtered: a caller sees only the ops it may use.
- Audit: `gateway.request_received`, `gateway.response_returned`.
- Security: arguments and `reason` are redacted before audit. The broker never inspects or materializes secrets.
- MCP is available two ways over the **same** authority. (1) A **client-side adapter**
  (`client/mcp_server.py`): a stdio bridge that translates MCP to the REST endpoints above
  and blocks per-process until approval resolves. (2) A **broker-native** `POST /mcp` route
  (`broker/mcp.py`) that terminates JSON-RPC (MCP) frames at the broker itself — stateless,
  non-blocking (a review op returns `pending_approval` + a request id, polled via
  `GET /v1/requests/<id>` exactly like REST), and bound by the same token auth. Both apply
  identical policy / approval / audit; over `/mcp` a denied or unknown op reads as
  `unknown tool` to the caller (least privilege) yet is audited exactly as on the REST path,
  auth failure is HTTP 401, and a per-caller throttle is HTTP 429. There is **no** approval
  callback route — resolution is poll-only by design (nod's callbacks are unauthenticated, so
  a receiver would be forgeable).

### 2. Broker → Tool container (forwarding)

```text
POST /v1/actions/<tool>.<op>  ->  POST http://127.0.0.1:<port>/v1/actions/<op>
```

- Both ingress framings converge here: whether a call arrived as REST `/v1/actions` or as a
  native MCP `tools/call` on `POST /mcp`, the broker terminates the agent-facing frame, checks
  policy, and makes this **one** REST call to the tool. Frames are never relayed verbatim to a
  tool — tools speak REST.
- The broker adds `broker_request_id` and `caller: {"name": "..."}`.
- **Optional per-tool shared secret (defense in depth, opt-in).** The broker may send an
  `X-Toolstack-Secret: <value>` header so the tool can verify the call came from the broker —
  not from another loopback process that guessed the tool's port and called it directly,
  bypassing policy/approval. The operator provisions the **same** value twice: the broker
  reads it from `TOOLSTACK_TOOL_SECRET_<TOOL>` (id upper-cased, non-alphanumerics → `_`;
  surrounding whitespace stripped on both sides; keep tool ids distinct under that
  normalization) and sends it (`broker/runtime.py`); the tool reads its copy from
  `$TOOLSTACK_SECRETS_DIR/broker_secret` (the toolyard injects it like any other field) and
  compares constant-time, replying `401` on mismatch. With neither side configured, no header
  is sent and the tool's check stays off — the feature adds nothing to the wire until enabled.
  This shared secret is the broker's **channel** credential for the hop; it is **not** a
  workload secret (the broker still never reads the secret backend — see §3 and the rule below).
- Audit: `runtime.execution_started`, `runtime.execution_completed`, `runtime.execution_failed`.
- Security: the broker attaches **no workload** secrets. The tool already holds its own; the
  only thing the broker may add is the optional channel shared secret above.

### 3. Toolyard → Secret backend (at container start)

Toolyard resolves that tool's fields and injects them into the container's
`/run/secrets/<name>` tmpfs at boot. Resolved values never persist to host disk. The
backend is pluggable via `$TOOLSTACK_SECRET_BACKEND` (`toolyard.secrets.get_backend`):
`file` (dev TOML), `vault` (a local **encrypted-at-rest** file — scrypt-stretched
passphrase + Fernet AEAD, for laptop/self-contained deploys; needs the `cryptography`
extra), or `infisical` (logs in with the per-tool machine identity). The broker holds no
backend credential for any of them.

### 4. Tool container → Toolyard (writable secrets)

Writable fields only, via `/run/toolyard/secrets.sock`. Toolyard enforces the
descriptor allowlist and patches exactly `(vault, item, field)`. No backend
credential is ever mounted in the container.

### 5. Broker ↔ nod (approval)

See [approval-surface-adapter.md](approval-surface-adapter.md). The broker owns
approval truth; nod is the messenger (poll-only — there is no callback route; the
broker's timeout wins).

### 6. Admin → operator clients (JSON API)

Distinct from the **agent-facing** broker REST (§1, bearer = a caller's broker token): the
admin also exposes an **operator** JSON API under `POST/GET /api/*` (`admin/api.py`) for native
/ automation clients — the same surface as the HTML panel (broker control, callers / policies /
tokens, observe), JSON in/out. Auth is `POST /api/login {password}` → a signed-session bearer
token (the same value the panel's cookie carries; no CSRF — a header token isn't auto-sent
cross-site). Every mutation goes through `broker.operations`, so the API, the HTML panel, and
`brokerctl` share **one** audit trail. Loopback-only, like the rest of the admin.

## Secrets access rule (collapsed)

Only **toolyard** talks to the secret backend, and only for **workload** secrets,
resolved at container start. The broker holds **no** secret-backend credential and
is never on the secret path. Component-to-component credentials / mTLS between hosts
are deferred (see [plan.md](../plan.md)).

## Audit event taxonomy

Append-only, written by the broker's Audit module. Families:

- `gateway.*` — `request_received`, `response_returned`
- `identity.*` — `token_validated`, `token_rejected` (per-request auth at the gateway;
  token *revocation* is an operator action, audited under `admin.token_revoked`)
- `registry.*` — `tool_lookup_failed`
- `policy.*` — `decision_allow`, `decision_deny`, `decision_review_required`
- `request.*` — `received`, `completed`, `denied`, `failed`, `expired` (one terminal
  event per request; the producing component also records its own runtime/policy/approval event)
- `approval.*` — `opened`, `approved`, `rejected`, `expired`, `surface_decision_received`,
  `unavailable`, `open_failed`
- `runtime.*` — `execution_started`, `execution_completed`, `execution_failed`
- `admin.*` — `caller_created`, `caller_revoked`, `policy_changed`, `token_issued`,
  `token_revoked`, `tool_created`, `tool_edited`, `tool_removed`; the admin web app also
  writes supervisory `admin.*` events: `broker_started/stopped/restarted`,
  `tool_started/stopped/restarted`

Together these answer the four audit questions: what did the agent ask for, what
was decided and by whom, what actually ran, and which credential made it possible.

## Redaction rules

- Arguments and tool results are redacted before they enter audit *or* an approval card.
- Raw tokens are never logged; any fingerprint is non-reversible.
- Nothing sensitive goes in a nod `title`/`summary` (push-visible); use `notification.redact`.

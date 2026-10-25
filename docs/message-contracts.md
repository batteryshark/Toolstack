# Message contracts

Source boundary **855da6e** (broker a9319b9, release integration 059dd13).
Read [integrated security contracts](security-contracts.md) for exact limits,
approval fields, receipt authority and offline retention/recovery procedures.

## Agent → broker

Bearer token identifies one caller. Only `GET /v1/health` is open (liveness only).
`GET /v1/tools` and `/v1/tools/<tool>.<op>` expose policy-filtered discovery.
`POST /v1/actions/<tool>.<op>` accepts `{arguments: {...}, reason: "optional"}`;
`GET /v1/requests/<id>` polls an owned request. Reason remains private, never sent
to Nod. Missing grants deny, including refresh/refresh_one.

HTTP action responses include 200 completed/result_expired, 202 received/executing/
pending_approval, 400 invalid (also duplicate Idempotency-Key headers), 403 denied,
404 not found, 409 idempotency conflict, 429 throttled, 502 unknown or tool failure/
unreachable, and 503 approval unavailable. Authorized GET receipts are 200 even for
unknown; withdrawn authority yields 403. Unknown means uncertain effect, NOT replay
permission. Legacy running displays as executing, never approval pending.

Optional `Idempotency-Key` is exactly `[A-Za-z0-9_-]{1,128}`, case-sensitive. Same
caller/key/payload returns original receipt with `reused: true`; changed payload
409; different caller independent. Additive fields are idempotency_key, reused,
payloads_pruned and wait-timeout broker_status. No-key requests are new effects;
CLI warns on stderr. Example: `toolstack call echo.say '{"a":1}' --idempotency-key
order-123 --wait`. A matching retry never resumes received work or dispatches,
even after generation changes. Private payload digest excludes generation/approval
nonce and is not the public nonce-bearing approval binding.

Historical receipt reads require current live caller/exact presented token and
current allow OR review grant; review is permission to read one's historical output,
not approval of a new effect. Deny/removal/revocation withholds output but cannot
retract bytes already returned. Immediate/deferred executing claims are conditional
transactional cancellation commit points. Store opening never relabels active work.

Client-side stdio MCP translates to HTTP and waits; broker-native `POST /mcp`
uses the same authority, nonblocking pending review and HTTP polling. Denied/unknown
ops appear as unknown tool over MCP. No approval callback route exists.

BOTH MCP entrances accept `tools/call.params._meta["toolstack/idempotency-key"]`,
not a workload argument. Stdio translates to HTTP header; native accepts header or
metadata, rejecting different simultaneous values as invalid params. Native payload
conflict is HTTP409 with isError true. MCP marks received/executing/unknown/conflict/
result_expired isError true. CLI incomplete/unknown/expired/conflict outcomes exit
nonzero. CLI/MCP wait on received/pending/executing only, bounded, stop on unknown;
timeouts preserve broker_status and receipt/key. Client transport/response loss
returns `status: unknown, source: client`, no retry; redirect remains refused and
unknown rather than implying original non-dispatch.

Schema3 receipts preserve key/private-digest tombstones indefinitely. Manual pruning
of terminal payloads strictly older than seven days retains active work and labels
payloads_pruned; completed becomes result_expired, unknown stays unknown. WAL/backups
are not secure erasure. Offline reconcile/restore require stopping ALL writers and
--confirm-offline. Restore only to NEW private destination, revoking ALL tokens,
clearing ALL policies, rotating UUID; never replay or overwrite original source.
See [exact commands and stale-history limits](security-contracts.md#manual-retention-and-offline-recovery).

Broker serial ingress: 10s absolute/3s idle, 64 KiB aggregate request-line/headers,
64 KiB ordinary body and 20 MiB REST hard ceiling before base64 expansion.
Transfer-Encoding/duplicate or malformed Content-Length refuse. Correlation IDs
must match `[A-Za-z0-9_-]{1,64}`, otherwise replaced; errors do not reflect exceptions.
Generic JSON checks precede policy; REST operation-specific checks follow authorization.

## Broker → tool

API forwards to loopback `/v1/actions/<op>`, MCP to `/mcp`, REST to `/sendrequest`.
Broker adds broker_request_id and caller metadata. `X-Toolstack-Secret` contains
the independently random channel credential read from dedicated channels.json;
tools compare to TOOLSTACK_CHANNEL_SECRET, **never SPS E_SECRET**. Broker never
falls back to private runner state. Same-account host access is still trusted.

REST sends `{op, arguments, broker_request_id, caller}` and receives
`{status, headers, body}` with body an opaque string, or an error envelope.
REST is not exposed over broker-native MCP. Response redaction is an explicit
author choice, not a consequence of writeback.

Workload HTTP execution defaults to 30 seconds (finite >0, <=300), 5s idle or
remaining time, and aggregate 32 MiB response bodies. MCP SSE is incremental and
requires matching JSON-RPC ID/type; workload isError propagates. DNS/JSON CPU are
not hard real-time cancellation. Timeout cannot roll back transmitted effects.

## Runner/tool → SPS → backend

Verified TLS/TCP, one JSON line each way, no HTTP/ALPN/multiplexing. Runner registers
declared mappings with broad SP_SECRET; per-start E_SECRET authorizes tool retrieval
and writable fields. Child gets TOOLSTACK_E_SECRET and SPS host/port/CA settings.
Inbound cap is 1 MiB including newline, not the response cap. Client response cap
defaults to 8 MiB including newline. Provider aggregate is 8 MiB across nested work;
default absolute socket budget 15s. See exact caveats in security contracts.

Providers remain localfile, infisical and hashicorp_vault; live compatibility is
unproved. Localfile encrypts at rest, not in endpoint memory. SPS restart loses
registrations; runner recovery must restore current authority. Cached values survive
revocation. No broker workload procurement does not mean secrets never reach broker:
results and same-account file/memory access may expose values.

## Broker ↔ Nod / operator API

See [adapter](approval-surface-adapter.md): poll-only, exact resolved option IDs,
persistent installation namespace, private reason, full-action/generation binding,
redirect refusal. Nod is trusted, not independently compromise-verified.

Admin `/api/*` uses an operator session bearer from `/api/login`, distinct from
caller tokens. HTML uses session cookie plus CSRF. Shared broker.operations owns
mutations/audit. Admin accesses SQLite directly; it is broader authority than agents.

Audit families cover gateway/identity/registry/policy/request/approval/runtime/admin.
Audit records bounded operational metadata; reason_provided is boolean, not reason.
Local audit can be deleted by authenticated host administrators and is not tamper-proof.
Masks are not a universal classifier. WAL/backups may retain cleared private data.

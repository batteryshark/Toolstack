# Work Log

## 2026-05-27

Started the greenfield Toolstack rebuild.

Completed:

- Defined the component decomposition.
- Added a threat-model-oriented component diagram.
- Added component I/O contracts.
- Added transport-neutral message contracts.
- Built a small Python stdlib-only scaffold with in-memory services.
- Added focused tests for the current ownership boundaries.
- Removed that scaffold after deciding it was too much of an all-in-one prototype for the desired one-component-at-a-time rebuild.
- Captured project working rules and component build order.

Important decisions:

- `BrokerGateway` only talks to `ClientProfileService` and `RequestService`.
- `BrokerGateway` has no direct secrets path.
- `RequestService` owns mutable request lifecycle state.
- `EventLoggingService` owns append-only audit/event history.
- `ToolRegistryService` has no secret awareness.
- Profiles can bind tools to secret namespaces through `SecretsManagementService`.
- `SecretsManagementService` also owns component-to-component credentials.
- Approval surfaces are external and pass through `Approval Surface Endpoint`.

Current verification:

No active test suite remains after removing the all-in-one scaffold.

Next likely step:

- Build `ClientProfileService` as the first isolated component.

Cleanup pass:

- Added `PROJECT.md` as the restart point.
- Added component plans and local coding standards.
- Removed the superseded scratch decomposition file.
- Removed the external clean-code reference bundle after distilling the project rules into `docs/coding-standards.md`.
- Removed generated `.DS_Store` and `__pycache__` files.
- Initially tried to curate project memory into Byterover, but sandbox/privacy policy blocked sending workspace docs to the external BRV daemon.
- After explicit user approval, successfully curated the project memory into Byterover. Task: `f2cc1e33-9371-4b7a-bb65-6f3a771d468c`; log: `cur-1779899631405`.
- Updated local Byterover context after removing the all-in-one scaffold so BRV no longer references `src/toolstack` or the deleted test file.
- Made `.brv/config.json` path-agnostic by changing `cwd` from an absolute machine path to `.`.
- Curated the corrected pre-implementation status into Byterover. Task: `af0ec935-c233-439e-bca1-8cad0f7d1843`; log: `cur-1779900640661`.
- Removed stale `pyproject.toml` before the initial GitHub publish because no active Python package exists yet.
- Decided to commit portable Byterover context by tracking `.brv/config.json` and `.brv/context-tree`, while leaving BRV runtime state and review backups ignored.
- Renamed the append-only audit component to `EventLoggingService` to clarify that it does not own active tool monitoring or alerting.

## 2026-06-13

Honest review of the systems diagram, then an architecture pivot.

Decisions:

- Reviewed the 11-box / 7-zone component diagram against the project's own values
  (simplicity, junior-readable, practical hardened security, easy deploy). It had
  over-decomposed the broker's safe interior into services while dropping the
  physical boundaries that were the real security. Chose to **collapse to
  deployment reality**.
- The earlier 9-service decomposition is preserved as **module seams inside the
  broker**, not separate services.
- Adopted **nod** (the user's self-hosted approval service) as the approval surface,
  via a thin adapter that lives inside the broker. This removes the separate
  approver process entirely.
- Corrected the tool-call topology: the broker forwards approved calls **directly to
  the tool container** on `127.0.0.1:port`; toolyard handles lifecycle + secret
  injection at container start and is not a request proxy.

Authored:

- `plan.md` — the concrete, component-by-component build plan (4 build / 3 deploy,
  build order, per-component plans, security invariants).
- `docs/approval-surface-adapter.md` — the approval-surface adapter contract so any
  surface can replace nod.

Doc reconciliation (made the set consistent with the collapse):

- Rewrote `README.md`, `PROJECT.md`, and `docs/component-decomposition.md`
  (physical-first diagram + broker-internals view + trust boundaries).
- Slimmed `docs/message-contracts.md` to the contracts that cross a process/trust
  boundary, plus standard outcomes, the collapsed secrets rule, audit taxonomy, and
  redaction rules.
- Deleted `docs/component-plans.md` and `docs/component-io-contracts.md` — fully
  superseded by `plan.md`.

Next step:

- Phase 0: tailnet ingress + a broker that binds localhost and fails closed.

## 2026-06-14

Built Phase 0 — the broker boundary.

Decisions:

- Stack: Python, **standard library only** (no framework, no dependencies). Runs
  with `python3 -m broker.server`. Matches the coding standards and the
  "boring/deployable/junior-readable" goals; framework choice stays deferred.
- The HTTP bind host is hard-coded to `127.0.0.1` (not configurable) so a
  misconfig can't expose the broker publicly. Port via `TOOLSTACK_BROKER_PORT`
  (default 8765).
- Kept decision logic pure (`gateway.handle`) and the HTTP transport thin
  (`server.py`) so the boundary is unit-testable without sockets.

Built (in `broker/`, as module seams, not services):

- `gateway.py` — ingress/egress, routing, correlation ids, the fail-closed rule.
- `identity.py` — caller/bearer seam; Phase 0 stub authenticates to None (deny).
- `audit.py` — in-memory append-only log; the running server attaches a stderr sink.
- `server.py` — localhost-bound `http.server` transport; suppresses version leak.
- Tests + `README.md`.

Behavior: `GET /v1/health` is the only open route (`{"status":"ok"}`); everything
else fails closed `401`; every request is audited (ingress + egress) without ever
logging the bearer value; each response carries `X-Correlation-Id`.

Verification:

- 16 tests pass: `python3 -m unittest discover -s broker/tests -t .` (also runnable
  with `pytest broker`).
- Live smoke confirmed health `200`, denied routes `401` (GET + POST), no Python
  version in the `Server` header, and audit events on stderr.

Next step:

- Phase 1 — broker core: Identity (callers + hashed tokens), Policy, Request
  lifecycle, and Audit-to-SQLite against a stub tool.

## 2026-06-14 — Phase 1 (broker core)

Built the broker core against a stub tool.

Added (in `broker/`, as module seams):

- `store.py` — SQLite: callers, tokens (hashed), caller_policies, requests,
  audit_events.
- `identity.py` — bearer parsing, SHA-256 token hashing, fail-closed
  `authenticate`; revoking a token or caller denies on the next request.
- `policy.py` — allow / review / deny with default-deny (pure).
- `registry.py` / `runtime.py` — Phase 1 stubs (`echo.say`); Phase 2 replaces them
  with `toolyard.toml` reading and container forwarding.
- `request_lifecycle.py` — registry → policy → execute, persisting request state
  and auditing each step; a `review` decision parks the request pending (Phase 3
  resolves it).
- `context.py` — shared dependency holder; `audit.py` now persists to SQLite (the
  server attaches the stderr sink).
- `gateway.py` — `POST /v1/actions/<tool>.<op>`, mapping outcomes to
  200/202/403/404/400/502.
- `admin.py` — minimal CLI to create a caller, issue a token (shown once), set policy.

Decisions:

- Tokens are stored only as SHA-256 hashes (appropriate for high-entropy random
  secrets); the raw token is shown once and never persisted or logged.
- Arguments and results are never persisted or audited (redaction invariant).
- A review-required op returns `202` and parks the request; no approver until Phase 3.
- `TOOLSTACK_BROKER_DB` selects the database path for the running server.

Verification:

- 40 tests pass: `python3 -m unittest discover -s broker/tests -t .`
- Live smoke (admin CLI + server): allowed `echo.say` → `200` with result; denied
  → `403`; missing/bad token → `401`; unknown tool → `404`; requests persisted
  (`completed` / `denied`); the bearer token never appears in the audit log.

Next step:

- Phase 2 — real tools: the Toolyard (read `toolyard.toml`, forward to a container
  on `127.0.0.1:port`, resolve per-tool secrets at container start).

## 2026-06-14 — Phase 2 (real tools)

Built the Toolyard and swapped the broker's stubs for real tool integration.

Decisions:

- Tool definitions are `toolyard.toml` (stdlib `tomllib`), not YAML — keeps both the
  broker and the toolyard dependency-free. Docs updated from `toolyard.yaml`.
- Pluggable runner: a `process` backend (zero-infra default; secrets in a private
  `0700` dir via `$TOOLSTACK_SECRETS_DIR`) and a `docker` backend (secrets at
  `/run/secrets`, port published to host loopback). Pluggable secret backend: a dev
  TOML `FileBackend` now; SOPS/Infisical behind the same `resolve()` later.
- The broker forwards directly to the tool (the toolyard is not a request proxy).

Broker changes:

- `registry.py` — reads tool/op/risk/port from `toolyard.toml` under
  `TOOLSTACK_TOOLS_ROOT`; never parses `[[secrets]]` (secret-unaware, tested).
- `runtime.py` — `HttpRuntime` forwards to `127.0.0.1:<port>/v1/actions/<op>` with
  `broker_request_id` + caller name; unreachable/non-2xx → 502.

New components:

- `toolyard/` — config, secrets (FileBackend), runner (Process + Docker), cli.
- `tools/echo_rest/` — a sample stdlib REST tool (the tool template) reading its
  secret from `$TOOLSTACK_SECRETS_DIR`, plus a Dockerfile.

Verification:

- 54 tests pass (46 broker + 8 toolyard); a docker e2e is opt-in via
  `TOOLSTACK_TEST_DOCKER=1` and ran green.
- End to end (process + docker): the broker forwards `echo.say` / `secret_status` to
  the toolyard-started tool; the tool reads its `api_key` (returns presence + length,
  never the value); the secret value appears **0 times** in the broker's audit/DB.
- Caught and fixed: a containerized tool must bind `0.0.0.0` (loopback for the host
  process), and container readiness needs an HTTP probe (the docker proxy accepts
  TCP before the app is serving).

Next step:

- Phase 3 — approval via nod: Approval orchestration + nod adapter resolving
  review-required requests; the broker owns approval truth; timeout fails closed.

## 2026-06-14 — Phase 3 (approval via nod)

Made the `review` decision actually gate execution behind a human in nod.

Decisions:

- **Poll is truth.** Resolution happens when the agent polls `GET /v1/requests/<id>`:
  the broker polls the surface, enforces its OWN timeout, and executes only on a
  confirmed approval. The optional `deliver` callback is deferred (documented) — it
  can't add authority, so poll-based is correct and simpler.
- The surface is pluggable (`ApprovalSurface`): `NodSurface` (HTTP) for production,
  `FakeSurface` for hermetic tests.
- Pending requests persist their arguments (needed to run after approval) in the
  control-plane DB, cleared at a terminal state; never audited and never in the card.

Added (broker/):

- `approval.py` — `OperationCard` (redacted prompt), `SurfaceState`, `build_card`.
- `surface_nod.py` — `NodSurface`: open (`POST /api/v1/requests`, issuer token,
  redacted card, `dedupe_key`), poll (`GET …/decision` → normalized state), cancel.
- `request_lifecycle.py` — review → `_open_approval`; `resolve_request` (poll +
  broker timeout + execute on approval); `execute_request` factored out and reused.
- `store.py` — `approvals` table; `requests` gains `arguments_json`/`result_json`/`error`.
- `gateway.py` — `GET /v1/requests/<id>` (owner-only) drives resolution; outcomes
  `expired` (200 on a status query) and `unavailable` (503).
- `context.py` / `server.py` — `surface` + `approval_ttl`; `NodSurface` built from
  `TOOLSTACK_NOD_URL` / `TOOLSTACK_NOD_TOKEN` / `TOOLSTACK_APPROVAL_TTL`.

Verification:

- 68 tests pass (broker) + 8 (toolyard): approval orchestration with a fake surface
  (pending/approve/reject/timeout/no-surface), the nod HTTP mapping against a fake
  nod server, and the gateway status route (incl. owner-only access).
- Live demo against a stand-in nod: allowed op runs immediately; a review op stays
  pending → approve → executes; reject → denied; with TTL=0 the broker fails closed
  to **expired even though nod approved**. The secret value appears 0 times in the
  broker's audit.

Next step:

- Phase 4 — admin + hardening: `brokerctl` / admin surface, redaction + revocation
  hardening, rate limits, and deferred items (deliver callback, tmpfs secret
  injection, temporary grants).

## 2026-06-14 — Phase 4 (admin + hardening)

Completed the planned build order (Phases 0–4).

Added (broker/):

- `brokerctl.py` — operator CLI (direct SQLite on the broker host, per the trust
  model): create/list/revoke callers, set/show policy, issue/list/revoke tokens,
  list requests, query audit. Replaces the minimal `admin.py`. Mutating actions are
  recorded as `admin.*` audit events.
- `redaction.py` — `redact()` bounds length and masks secret-like runs; applied to
  the caller's `reason` before it enters audit.
- `ratelimit.py` — per-caller fixed-window limiter; the gateway returns `429` over
  the limit (`TOOLSTACK_RATE_LIMIT`, default 120/min, 0 = off).
- `store.py` — operator queries (callers/tokens/requests) and request/correlation
  audit filters + `recent_audit`.

Decisions:

- The operator surface is a direct-DB CLI, not a networked admin API — matches the
  trust model ("operator on the broker host"), so there's nothing extra to secure.
- Revocation was already immediate (token/caller checked per request); Phase 4 adds
  the CLI path and an end-to-end test.

Verification:

- 78 broker + 8 toolyard tests. New: redaction, rate limiter, brokerctl flows
  (create → authenticate, revoke-token/caller → next auth denied, admin audit
  recorded), gateway 429 + reason redaction, and an audit-trail-answers-the-four-
  questions test.
- Live demo: brokerctl create/list/show; per-caller rate limit (3rd call → 429);
  revoke-token → next call 401; audit shows received/policy/runtime for a request
  with the `reason` redacted (`rotate key [redacted]`, raw token absent); admin
  actions audited.

Deferred (documented, for deployment hardening):

- Approval `deliver` callback (latency fast-path; poll-based resolution is in place).
- Container **tmpfs** secret injection (Phase 2 writes to a 0700 dir / bind mount).
- Temporary grants / JIT elevation; background approval-expiry sweeper.
- Component credentials / mTLS only if modules split across hosts.

## 2026-06-14 — Agent client + tool discovery + approval round-trip

Built the agent-side shim (was missing — we only had the broker's server surface)
and closed the nod note round-trip.

Decisions:

- **Hybrid client shape:** one generic `toolstack` CLI for all tools (the default),
  with optional per-domain skills only where a domain needs rich guidance. Token
  efficiency comes from **lazy discovery** — schemas are fetched on demand, not
  carried in context.
- **Discovery is policy-filtered:** a caller sees only the ops it may use
  (least privilege + smaller surface).
- **Comments are reactive and sparse** (baked into the skill): no `reason` on
  allowed ops; one short `reason` on review ops; on a rejection, read the note and
  retry at most once with a reason that responds to it.

Added:

- `client/toolstack.py` — stdlib CLI: `tools`, `describe`, `call`, `wait`, `whoami`
  (URL + token from env). `client/SKILL.md` — the tiny generic skill.
- Broker discovery: `GET /v1/tools` (the caller's allowed ops + effect/risk/desc) and
  `GET /v1/tools/<tool>.<op>` (args on demand), both policy-filtered.
- `toolyard.toml` operations now carry `description` + optional `args`; the registry
  reads them (still ignores `[[secrets]]`) and exposes `describe` / `list_ops`.
- **Note round-trip:** the approver's `approver`/`note` are surfaced in the request
  status response (approve *and* reject), and the agent's (redacted) `reason` rides
  to the nod card as the human-visible justification.

Verification:

- 97 tests (83 broker + 8 toolyard + 6 client). New: discovery (filtered list +
  describe + denied→404), approver-note-surfaced + reason-to-card, and a client
  end-to-end (discover → call → review → wait, note returned).
- Live demo via the `toolstack` client against a stand-in nod: `whoami` / `tools` /
  `describe` / `call` (allow runs now) / review → `wait` returns the result **plus
  the approver and note**; the rejection note also reaches the agent.

## 2026-06-14 — Robust argument input + MCP adapter

Addressed the agent→client fragility: passing JSON as a quoted shell argument breaks
on quotes/newlines/`$`. The fix is to keep structured data out of the shell.

- **CLI input (`toolstack call`)** now reads the JSON arguments from, in order:
  `--args-file`, then **stdin** (the quoted-heredoc idiom — passes the body literally),
  then an inline positional (trivial cases only). The skill teaches heredoc/file as
  the default.
- **MCP adapter (`client/mcp_server.py`)** — a stdio JSON-RPC server: `tools/list`
  maps the caller's allowed broker ops (input schemas from each op's args) and
  `tools/call` forwards to the broker, blocking on approval and returning the result
  plus the approver's note. The agent passes a structured `arguments` object, so there
  is **no shell and no quoting risk** — the most robust path.

Robustness ranking (documented): native/MCP (no shell) > heredoc→stdin / `--args-file`
> named flags (partial) > inline JSON arg (fragile).

Verification:

- 15 client tests (CLI incl. stdin + args-file with tricky data; MCP incl. tools/list
  mapping, allowed call, review→approve/reject with note, JSON-RPC error, notification).
- Live smoke of the MCP stdio loop: initialize / tools/list / tools/call passed
  `hi via mcp, with 'quotes' & $stuff` through cleanly with no escaping.

## 2026-06-14 — Admin web app (run the broker, manage clients/tools)

Built the operator control panel: a FastAPI app (the one component allowed runtime
deps) that **supervises the broker process**, manages callers/tokens/policies and
tools, and shows requests + audit. Local/homelab, loopback-only. Because the broker
has no admin API, the panel reaches state two ways — it opens the broker `Store`
directly and mutates through a new shared `broker/operations.py` (so the panel and
`brokerctl` write **one** `admin.*` audit trail), and it supervises the broker (and
tools) as child processes, mirroring `toolyard.runner` (`posix_spawn` + `killpg` +
a `/v1/health` probe).

- **Shared foundation** — `broker/operations.py` extracted from `brokerctl` (policy
  build, create/revoke caller, set policy, issue/revoke token; missing caller →
  `LookupError`); `brokerctl` rewired to thin wrappers; `broker/store.py` now sets
  WAL + `busy_timeout` so the broker's long-lived connection and the panel's
  short-lived ones share the file safely.
- **Auth** — ported scrypt password + HMAC session, plus a session-bound **CSRF**
  token on every POST (the old panel had none); fail-closed (`set-password` required,
  no default login); `HttpOnly` + `SameSite=Strict`.
- **Supervisor + run config** — `BrokerRunConfig` (every `TOOLSTACK_*` the broker
  reads) persisted to TOML; broker stdout/stderr captured to a log; nod token
  write-only / masked, never echoed back.
- **Tools** — start/stop/restart via the toolyard, sharing its state file; the panel
  prompts to restart the broker to register a newly added tool (registry read at start).
- **Audit hygiene** — the broker no longer audits `GET /v1/health`; liveness probes
  (which the panel polls on every render) were burying the real trail.

Verification:

- 32 admin tests (auth / session / CSRF, run-config TOML round-trip + masking, a
  **real broker** start/stop/restart via the supervisor, toolyard listing, and a full
  login → create-caller → set-policy flow via FastAPI's TestClient). 148 tests total
  across broker / toolyard / client / admin.
- Live HTTP smoke (uvicorn), then a full **panel → broker → tool → client**
  walkthrough: the panel started the broker and the real echo tool, created a caller
  and policy, and `toolstack call echo.say` returned `{"echoed": {"m": "hi there"}}`,
  with `admin.*` events visible to both the panel and `brokerctl`.

## 2026-06-14 — Tool authoring & editing in the panel

Extended the admin app so an operator can **add a tool by naming a directory and
filling in a form** (and edit existing tools) — the panel builds the `toolyard.toml`.
Per the chosen scope it writes the **manifest only** (the operator brings the tool's
code or image), to **any absolute server path** (so the broker had to learn to
discover tools from more than one place), and the secret editor authors only secret
*declarations* — values stay in the on-disk secrets file.

- **Broker discovery** — `Registry.from_sources(root, tool_dirs)` adds explicit
  per-tool directories alongside the tools-root glob; `broker/server.py` reads
  `TOOLSTACK_TOOLS_DIRS` (an `os.pathsep` list). Back-compatible: no var → unchanged.
- **Run config** — `BrokerRunConfig.tool_dirs` (a TOML array) feeds that env; the
  panel appends a newly authored directory and prompts a broker restart to register it.
- **Authoring** — `admin/tool_authoring.py` parses the editor's payload, validates
  (id/port/op-name/risk), and serializes idiomatic TOML; tests confirm the written
  file is consumable by the broker registry *and* the toolyard config loader.
- **Editor UI** — a form with real widgets for repeating operations/arguments/secrets
  (vanilla JS assembles them into one hidden JSON field on submit, so no hand-typed
  TOML or JSON), pre-filled from the existing manifest when editing.

Verification:

- 173 tests total (broker 96, toolyard 8, client 15, admin 54), including authoring
  round-trips, multi-dir registry discovery, and the editor routes via TestClient.
- Live walkthrough: through the panel, authored a new tool's `toolyard.toml` into a
  named directory, started the broker (which registered it) and the tool, then
  `toolstack call myecho.say` returned `{"echoed": {"m": "hello new tool"}}`; editing
  the tool's risk in the panel persisted to its `toolyard.toml`.

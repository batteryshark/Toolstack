# Toolstack — Walkthrough & Review

A self-contained review of where the project stands after Phases 0–4, the agent
client, and the admin web app. Read this to re-orient, verify the work is sound, and
decide what's next. Companion docs: [PROJECT.md](../PROJECT.md) (nerve center),
[plan.md](../plan.md) (build plan), [component-decomposition.md](component-decomposition.md)
(architecture), [admin/README.md](../admin/README.md) (the control panel).

## TL;DR

The planned build order (Phases 0–4) is **complete and tested**, the agent-side
client (the `toolstack` CLI + MCP adapter + skill) is built on top, and an operator
**admin web app** now runs and manages the whole stack — 253 tests pass
(132 broker + 40 toolyard + 23 client + 58 admin), incl. opt-in Docker runner tests
and an opt-in live-nod test, with live walkthroughs end to end. The full vertical slice runs:

> **agent → broker (auth + policy) → human approval in nod → tool execution with
> its own workload secrets — and the broker never sees a secret.**

The broker, toolyard, and client are **zero-dependency stdlib Python** (Docker only
for the production tool runner), runnable with `python3`. The admin app is the one
component that carries runtime deps (FastAPI + uvicorn, in its own venv). It is
**not yet deployment-hardened** — see [Deferred & caveats](#deferred--caveats)
before running it anywhere real.

## Contents

1. [The one idea](#the-one-idea)
2. [Architecture at a glance](#architecture-at-a-glance)
3. [What's built](#whats-built)
4. [The request lifecycle, end to end](#the-request-lifecycle-end-to-end)
5. [Security properties & evidence](#security-properties--evidence)
6. [Run it](#run-it)
7. [Test it](#test-it)
8. [Design decisions to confirm](#design-decisions-to-confirm)
9. [Deferred & caveats](#deferred--caveats)
10. [File map](#file-map)
11. [Review checklist](#review-checklist)

---

## The one idea

> **Trust agents with action, not access.** The agent can *ask*; the broker
> *decides*; tools *execute*; secrets live with the tools. The agent can reach the
> broker and nothing else.

Everything below serves that sentence. The security comes from **physical
boundaries** (one ingress, localhost binding, secrets resolved at the workload),
not from rules on paper.

---

## Architecture at a glance

```mermaid
flowchart TB
    subgraph Untrusted["Agent host — untrusted"]
        Agent["Agent / client<br/>holds only a low-power broker token"]
    end
    Ingress["Tailnet / VPN ingress<br/>— the ONLY path in —"]
    subgraph BrokerHost["Broker host — authority boundary"]
        Broker["Broker (one process)<br/>auth · policy · request lifecycle<br/>approval orchestration · audit"]
        DB[("SQLite<br/>callers · tokens · requests<br/>approvals · audit")]
        Admin["Admin web app<br/>operator · loopback only<br/>runs the broker · clients · tools · audit"]
    end
    subgraph Workload["Tool runtime — execution boundary"]
        Toolyard["Toolyard<br/>container lifecycle + secret resolution<br/>(not in the request path)"]
        Tools["Tool containers<br/>127.0.0.1:port · secrets at /run/secrets"]
    end
    Nod["nod<br/>approval surface (external)"]
    Vault["Secret backend<br/>Infisical / SOPS (external)"]

    Agent --> Ingress --> Broker
    Broker --> DB
    Broker -->|forward approved call| Tools
    Toolyard -->|start + inject secrets| Tools
    Broker <-->|open / read decision| Nod
    Toolyard -->|resolve secrets| Vault
    Broker -. never on the secret path .-> Vault
    Admin -. supervise process .-> Broker
    Admin --> DB
```

**Trust boundaries:** agent → broker (tailnet, one-caller bearer token); broker →
tool container (localhost); toolyard → secret backend (per-tool identity on the
host); tool → secret backend (none — it reads files); broker → nod (issuer token on
the broker host); operator → broker (`brokerctl`, or the **admin web app** — both
direct on the host, the panel over loopback with a login).

The broker is **one process with internal module seams** (not a service mesh). The
request path is broker → tool container *directly*; the toolyard starts tools and
injects their secrets but is not a proxy. The admin app is not in the request path:
it **supervises the broker process** and reads/writes the same SQLite file directly
(the broker has no admin API), so it never widens the attack surface the agent sees.

---

## What's built

### You build these

| Component | Where | Role |
|---|---|---|
| **Broker** | [broker/](../broker/) | Authority boundary: auth, policy, request lifecycle, approval orchestration, audit, admin. One process, one SQLite file. |
| **Toolyard** | [toolyard/](../toolyard/) | Execution boundary: reads `toolyard.toml`, resolves secrets, runs tools (process or docker). |
| **Tool template** | [tools/echo_rest/](../tools/echo_rest/) | A sample standalone REST tool that reads its own secret. |
| **Agent client** | [client/](../client/) | The generic `toolstack` CLI + skill an agent uses to discover and call tools (lazy discovery; hybrid with optional per-domain skills). |
| **Admin web app** | [admin/](../admin/) | Operator control panel (FastAPI): supervises the broker process, manages callers/tokens/policies, authors/edits/removes tools, shows requests + audit. Loopback-only; the one component with runtime deps. |

Broker internal modules (each keeps its "owns / must not" rule):

| Module | Responsibility |
|---|---|
| [gateway.py](../broker/gateway.py) | HTTP ingress/egress, routing, correlation ids, body validation, rate-limit + redaction entry points (liveness probes not audited) |
| [identity.py](../broker/identity.py) | callers + SHA-256-hashed bearer tokens; fail-closed `authenticate` |
| [policy.py](../broker/policy.py) | `allow` / `review` / `deny`, default-deny (pure) |
| [registry.py](../broker/registry.py) | reads tool/op/risk/port from `toolyard.toml`; ignores `[[secrets]]`; discovers tools from the tools root **and** explicit tool dirs |
| [request_lifecycle.py](../broker/request_lifecycle.py) | registry → policy → execute, with the approval detour and deferred execution |
| [approval.py](../broker/approval.py) | the operation card + normalized surface state (adapter contract) |
| [surface_nod.py](../broker/surface_nod.py) | `NodSurface`: the HTTP adapter to nod (open / poll / cancel) |
| [store.py](../broker/store.py) | SQLite persistence (WAL, so the broker and admin app share the file) + operator/audit queries |
| [operations.py](../broker/operations.py) | operator mutations (create/revoke caller, set policy, issue/revoke token) + `admin.*` audit — shared by `brokerctl` and the admin app |
| [audit.py](../broker/audit.py) | append-only audit log (stderr sink when serving) |
| [ratelimit.py](../broker/ratelimit.py) · [redaction.py](../broker/redaction.py) | per-caller rate limiting · free-text redaction |
| [server.py](../broker/server.py) · [brokerctl.py](../broker/brokerctl.py) | HTTP transport (binds localhost) · operator CLI |

### The admin web app

Because the broker exposes **no admin API** (only health / actions / tools / requests),
the panel reaches broker state two ways: it **supervises the broker process**
(`posix_spawn` / `killpg` / `/v1/health`, mirroring the toolyard runner) from a
persisted run-config, and it opens the broker's SQLite `Store` **directly** — mutating
through `broker.operations`, the same path `brokerctl` uses, so the panel and the CLI
write **one** `admin.*` audit trail. It authors tools by writing a `toolyard.toml`
into a directory you name (registered via `TOOLSTACK_TOOLS_DIRS`, picked up on the next
broker restart). It binds `127.0.0.1` only, gates every page on a signed session
(scrypt password + HMAC cookie) with a CSRF token on every POST, and keeps secrets off
the browser (nod token write-only/masked; tool secret *values* are never entered there).
Modules: [admin/README.md](../admin/README.md).

### You deploy these (external)

- **nod** — the self-hosted approval surface ([batteryshark/nod](https://github.com/batteryshark/nod)).
- **Secret backend** — Infisical or SOPS (Phase 4 ships a dev TOML `FileBackend`).
- **Tailnet** — Tailscale Serve (or any VPN); the ingress boundary.

---

## The request lifecycle, end to end

1. Agent `POST /v1/actions/<tool>.<op>` with a bearer token (over the tailnet).
2. **Gateway** authenticates the token → caller (else `401`); rate-limits the
   caller (else `429`).
3. **Registry** resolves the tool/op (else `404`).
4. **Policy** decides:
   - **deny** → `403`, request recorded `denied`.
   - **allow** → **execute now**: forward to the tool container, return `200` + result.
   - **review** → open a **nod** decision, persist the request `pending_approval`,
     return `202` + `request_id` (or `503` if no surface configured).
5. For review, the agent polls `GET /v1/requests/<id>`:
   - broker enforces its **own timeout** (past deadline → `expired`, fail closed);
   - else polls nod: **approved** → execute → `ok`; **rejected** → `denied`;
     still pending → `pending_approval`.
6. Every step is appended to the **audit log**; the operator reads it with
   `brokerctl audit`.

Arguments are persisted only while a request is pending approval (needed to run it
later), cleared at a terminal state, and **never audited**.

The agent discovers callable ops via `GET /v1/tools` and `GET /v1/tools/<tool>.<op>` (policy-filtered —
it only sees what it may use) and uses the `toolstack` client to call them. A
reviewed request's status response carries the approver's **note** back, so the
human's reason for approving or rejecting reaches the agent.

---

## Security properties & evidence

Each invariant, how it's enforced, and the test that proves it.

| Property | Enforcement | Evidence |
|---|---|---|
| Agent reaches only the broker | binds `127.0.0.1` (not configurable); tailnet is the sole ingress | `test_server.test_bound_to_localhost_only`; live demos |
| Fail closed | no caller → `401`; no policy grant → `403` (default-deny); no surface → `503`; timeout → `expired`; tool down → `502` | `test_gateway`, `test_policy`, `test_lifecycle`, `test_approval`, `test_runtime` |
| Secrets never on the control plane | broker holds no backend credential; registry ignores `[[secrets]]`; toolyard injects secrets to the tool | `test_registry.test_registry_is_secret_unaware`; `toolyard…test_runner` (tool reads secret, value not returned); Phase 2/3/4 demos show **0** occurrences in audit |
| Tokens hashed; revocation immediate | only SHA-256 stored; per-request token+caller check | `test_identity` (revoked token/caller denied); `test_brokerctl` (revoke → next auth denied) |
| Redaction | args/results never audited; `reason` redacted; tokens never logged | `test_lifecycle.test_arguments_never_appear_in_audit`, `test_gateway.test_reason_is_redacted_in_audit` |
| Broker owns approval truth; timer wins | poll is authoritative; broker timeout ignores a late approval | `test_approval.test_timeout_fails_closed_even_if_surface_says_approved`, `…gates_execution`, `…rejection_denies` |
| Every decision auditable (4 questions) | gateway/request/policy/runtime/approval/admin events, queryable by request id; liveness probes excluded as noise | `test_lifecycle.test_audit_trail_answers_the_questions`; `test_operations` (admin.* events); `test_gateway.test_health_is_not_audited` |
| Abuse control | per-caller fixed-window rate limit | `test_ratelimit`, `test_gateway.test_rate_limit_returns_429` |
| Admin panel is contained | binds `127.0.0.1`; scrypt password + HMAC session + CSRF on every POST; fail-closed (no password set → refuses to start); nod token / tool secrets never rendered back | `admin…test_auth` (session/CSRF), `test_app` (login gate, CSRF rejection), `test_broker_config` (token masked) |

The "four audit questions" (what was asked / decided & by whom / actually ran /
which credential) are answerable via `brokerctl audit --request-id <N>`: a request
carries `request.received` → a `policy.*`/`approval.*` decision → `runtime.*` execution
→ a terminal `request.{completed,denied,failed,expired}`, and each authenticated call
emits `identity.token_validated` with a non-reversible token fingerprint (the "which
credential" answer); a rejected bearer emits `identity.token_rejected`.

---

## Run it

Two ways, both from the repo root: the **admin panel** (easiest — it runs the broker
and tools for you) or the **CLI** (zero-dependency, scriptable).

### The admin panel

```bash
python3 -m venv admin/.venv && admin/.venv/bin/pip install -r admin/requirements.txt
admin/.venv/bin/python -m admin set-password         # required (fail closed)
admin/.venv/bin/python -m admin serve                # http://127.0.0.1:8780
```

Then in the browser: set the run-config (tools root, nod URL/token), **Start** the
broker, create a caller (copy its one-time token), edit its policy, and add/start
tools. Only the panel uses its venv; the broker, toolyard, and client it drives are
still zero-dependency stdlib.

### The CLI (zero dependencies — Python 3 only)

```bash
# 1. start a tool (toolyard resolves its secret from the dev backend and runs it)
cp secrets.example.toml secrets.toml
python3 -m toolyard.cli up echo --secrets secrets.toml
python3 -m toolyard.cli ls

# 2. create a caller (token printed once)
python3 -m broker.brokerctl create-caller --name hermes --allow echo.say

# 3. start the broker pointed at the tools root (rate limit on by default)
TOOLSTACK_TOOLS_ROOT=tools python3 -m broker.server     # listens on 127.0.0.1:8765
```

```bash
# 4. call it (another shell)
TOKEN=<token from step 2>
curl -s -X POST http://127.0.0.1:8765/v1/actions/echo.say \
     -H "Authorization: Bearer $TOKEN" -d '{"arguments": {"m": "hi"}}'
# -> {"status":"ok","request_id":1,"result":{"echoed":{"m":"hi"}}}

python3 -m broker.brokerctl audit --request-id 1     # the full trail
python3 -m toolyard.cli down echo
```

**Approval flow** needs a nod (or a stand-in). Set `TOOLSTACK_NOD_URL` +
`TOOLSTACK_NOD_TOKEN` on the broker and give the caller a `--review <tool>.<op>`;
without a surface, review ops return `503`. Key env vars: `TOOLSTACK_BROKER_PORT`,
`TOOLSTACK_BROKER_DB`, `TOOLSTACK_TOOLS_ROOT`, `TOOLSTACK_TOOLS_DIRS` (extra per-tool
dirs, `os.pathsep`-separated), `TOOLSTACK_NOD_URL`/`_TOKEN`, `TOOLSTACK_APPROVAL_TTL`,
`TOOLSTACK_RATE_LIMIT`. Operator commands and the tailnet step are in
[broker/README.md](../broker/README.md) and [toolyard/README.md](../toolyard/README.md).

---

## Test it

```bash
python3 -m unittest discover -s broker/tests -t .        # 132 tests (1 live-nod skipped)
python3 -m unittest discover -s toolyard/tests -t .       # 40 tests (3 docker + 1 live-Infisical skipped)
python3 -m unittest discover -s client/tests -t .         # 23 tests (CLI + MCP, vs a real broker)
TOOLSTACK_TEST_DOCKER=1 python3 -m unittest toolyard.tests.test_runner   # + 3 real-container tests

# the admin app (needs its venv): 58 tests
admin/.venv/bin/python -m unittest discover -s admin/tests -t .
```

Coverage by area: identity/auth + revocation, policy + default-deny, the full
request lifecycle (allow/deny/review/unknown/tool-failure + status transitions),
registry secret-unawareness and multi-dir discovery, HTTP forwarding, approval
orchestration (approve / reject / timeout / no-surface) and the nod HTTP mapping,
the gateway routes and hardening (429 + redaction + health not audited), the shared
operator mutations, and the toolyard (config / secrets / process runner end-to-end /
docker). The admin suite covers auth / session / CSRF, the run-config round-trip, a
**real broker** start/stop via the supervisor, tool authoring (and that the written
`toolyard.toml` is consumable by the broker registry), and a full login →
create-caller → set-policy flow via FastAPI's TestClient.

---

## Design decisions to confirm

These are judgment calls made along the way — worth a deliberate yes/no:

1. **Collapse to deployment reality.** The earlier 9-service decomposition became
   module seams inside one broker process. *Why:* security from physical
   boundaries, not paper rules; far simpler to deploy/understand.
2. **Zero-dependency stdlib Python** (no web framework; `http.server`). *Why:* "just
   `python3`", boring, junior-readable. Confirm this still fits as the broker grows.
3. **`toolyard.toml` (not `toolyard.yaml`).** *Why:* YAML would force a PyYAML
   dependency on both broker and toolyard; TOML is stdlib (`tomllib`). *This deviates
   from the original docs* — confirm you're happy with TOML.
4. **Caller model, no profiles.** Identity is caller + token (the old design's
   profiles were dropped). Confirm a single policy bundle per caller is enough.
5. **nod via a pluggable adapter; poll-only by design.** Resolution is poll-based
   (`GET /v1/requests/<id>`). A push/callback fast-path is deliberately not built
   and not planned: nod posts callbacks unauthenticated, so a broker receiver would
   let anyone forge an approval. Confirm poll-only is the resolution model you want.
6. **Process + Docker runners; dev file secret backend.** Process backend is the
   zero-infra default; Docker is the production path; SOPS/Infisical are the
   production secret backends (not yet wired).
7. **Rate limit default 120/caller/min.** Tune to taste (`TOOLSTACK_RATE_LIMIT`).
8. **Admin app carries deps (FastAPI) and supervises the broker.** It's the one
   component allowed runtime deps (its own venv), runs the broker as a child process,
   and reads/writes the SQLite file directly (the broker has no admin API). *Why:* a
   real control plane for homelab use without burdening the stdlib core. Confirm
   you're happy with a deps-carrying panel alongside the zero-dep core.
9. **Tools can live at any server path; the panel writes only the manifest.** "Add a
   tool" writes a `toolyard.toml` into a directory you name (registered via
   `TOOLSTACK_TOOLS_DIRS`); you supply the code or image. *Why:* you chose any-path
   over root-only. Confirm that's still the model you want.

---

## Deferred & caveats

Honest list of what is **not** done — none block the slice working, but they matter
before a real deployment:

- **Secrets touch host disk transiently.** The process runner writes secrets to a
  `0700` temp dir; the docker runner bind-mounts a host dir — both removed on stop.
  Production hardening: inject into a container **tmpfs** at start (no host disk).
- **Approval `deliver` callback** deliberately not built and not planned — a design
  decision, not a gap. `poll` is the sole source of approval truth; a receiver of
  nod's unauthenticated callback would be forgeable (anyone reaching it could forge
  an "approved"). Poll-only closes that hole.
- **Expiry/revocation are lazy, not a background worker.** A pending request expires on
  its next poll, on any new `submit` (which sweeps all stale approvals), or via
  `brokerctl sweep`; revoking a caller/token cancels its pending approvals eagerly. There
  is still no always-on background thread — an unattended, never-swept request lingers
  until the next submit or a manual sweep (fine: the single-threaded broker stays simple).
- **Single-threaded broker serving.** The broker's `HTTPServer` serves one request at
  a time. SQLite is now in **WAL mode**, so the admin app's short-lived connections
  safely coexist with the broker's long-lived one; but concurrent *serving inside the
  broker* would still need a connection pool + locking (the in-memory rate limiter too).
- **Admin app is single-operator.** One login (scrypt password + HMAC session); no
  multi-user, roles, or SSO. Loopback-only and no TLS of its own — reach it over a
  tunnel that terminates TLS, never a public bind.
- **No DB migrations.** The schema grew across phases via `CREATE TABLE` / new
  columns; assume a **fresh DB** when upgrading a dev instance (delete the sqlite file).
- **nod API contract — verified.** The create / decision-read / cancel shapes in
  `surface_nod.py` are pinned against nod **v1.0.1** (`nod-proto` crate, commit
  `01d535d`): every request field and response key was checked against that
  source and the base routing live-probed against a running instance. The default
  test suite exercises the mapping against a wire-faithful fake; an opt-in live
  test (`test_surface_nod_live.py`, skipped unless `TOOLSTACK_NOD_URL` /
  `TOOLSTACK_NOD_TOKEN` are set) drives a real open→poll→cancel cycle. Re-verify
  if you bump the nod version — the create body is `deny_unknown_fields`.
- **Rate limiter is in-memory, per process.** Resets on restart; not shared across
  broker instances.
- **Temporary grants / JIT elevation** not implemented (policy is static
  allow/review/deny).

---

## File map

```
PROJECT.md            nerve center / restart point
plan.md               component-by-component build plan (+ build-order status)
README.md             front door
secrets.example.toml  dev secret backend template (copy to secrets.toml)
docs/
  walkthrough.md          this document
  component-decomposition.md  diagrams + trust boundaries
  message-contracts.md        boundary wire contracts, outcomes, audit taxonomy
  approval-surface-adapter.md the approval-surface "SDK" (write another surface)
  coding-standards.md         clean-code expectations
  work-log.md                 dated history (Phases 0–4 → admin app)
broker/               the authority boundary (see module table above; + operations.py) + tests/
toolyard/             config.py · secrets.py · runner.py · cli.py + tests/
tools/echo_rest/      sample tool: app.py · toolyard.toml · Dockerfile
client/               agent client: toolstack.py (CLI) · mcp_server.py (MCP) · SKILL.md + tests/
admin/                control panel (FastAPI): server · views · auth · supervisor ·
                      broker_config · tool_authoring · toolyard_ops + tests/ + .venv (gitignored)
deploy/               systemd unit template · env example · redeploy script · README (real install)
pyproject.toml        packages the stdlib CLIs (toolstack/brokerctl/toolyard) for `pip install -e .`
```

---

## Review checklist

Tick these tomorrow to confirm we're in a good place:

- [ ] **Tests green:** run all four suites (broker / toolyard / client, plus the
      admin venv suite), and the docker e2e if Docker is up.
- [ ] **It runs:** do the [Run it](#run-it) quickstart; see `echo.say` return a result.
- [ ] **Admin panel:** `admin/.venv/bin/python -m admin serve`, log in, **Start** the
      broker, create a caller, **Add** a tool — confirm the broker registers it after a
      restart and the client can call it.
- [ ] **Agent path:** with a broker running, `python3 -m client.toolstack tools` then
      `call` a tool; confirm an approver's note comes back on a reviewed op.
- [ ] **Approval works:** wire a nod (or the fake-nod approach from the Phase 3
      work-log) and watch a `review` op gate on approve / reject / timeout.
- [ ] **Security invariants:** skim [Security properties & evidence](#security-properties--evidence)
      and spot-check one or two tests.
- [ ] **Boundaries hold:** skim each broker module's "owns / must not" in
      [plan.md](../plan.md) and confirm the code matches.
- [ ] **Decisions:** confirm the nine [design decisions](#design-decisions-to-confirm)
      — especially TOML, no-profiles, poll-only approval, and the deps-carrying admin app.
- [ ] **Deferred list acceptable:** agree the [caveats](#deferred--caveats) are OK to
      defer for now, and flag any that must move up before deployment.
- [ ] **nod reality check:** verify `surface_nod.py`'s endpoints/shapes against the
      real nod API before any deployment.
- [ ] **Decide next:** the build is committed and pushed (branch `admin-web-app`, PR
      open); pick a hardening item or wire a real deployment (nod + secret backend + tailnet).

If those pass, we're in a good place: a working, tested, honestly-scoped vertical
slice with an operator control plane, and the security properties enforced where it
counts.

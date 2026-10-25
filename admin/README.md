# Admin web app

The operator's control panel for the whole stack: **run the broker**, **manage
clients** (callers, tokens, policies), **control tools**, and watch **requests and
audit**. Built for local / homelab use; binds loopback only. See [../plan.md](../plan.md).

This is the one Toolstack component with runtime dependencies (FastAPI + uvicorn,
plus PyYAML for YAML OpenAPI imports); the broker, toolyard, and client stay
zero-dependency stdlib. Because the broker has no admin API, the panel reaches
broker state two ways:

- **data**: opens the broker's SQLite `Store` directly (exactly as `brokerctl`
  does) and mutates through `broker.operations`, so the panel and the CLI share one
  audit trail;
- **lifecycle**: supervises the broker (and tools) as child processes via
  `os.posix_spawn` / `killpg`, mirroring `toolyard.runner`.

## Set up

```bash
python3 -m venv admin/.venv
admin/.venv/bin/pip install -r admin/requirements.txt
admin/.venv/bin/python -m admin set-password      # required: fail closed, no default login
```

## Run

```bash
admin/.venv/bin/python -m admin serve             # http://127.0.0.1:8780  (--port to change)
```

Run it from the repo root, so it can import the broker/toolyard packages and resolve
a relative tools root. Then sign in and:

1. set the broker **run config** (tools root, nod URL/token, ...) and **Start** the broker;
2. create **callers**, copy each one-time token, and edit a caller's **policy**
   (allow / review / deny per operation);
3. **Manage tools**: **Add tool** writes a `toolyard.toml` from a form (id, entrypoint
   command/port or image, operations, and secret *declarations*) into a directory you
   name on the server. REST tools can be authored directly or bootstrapped from a
   pasted OpenAPI/Swagger spec. **Edit** loads an existing tool back into that form; **Remove**
   unregisters an external tool directory (stops it and removes that configured source;
   its files stay on disk), or deletes a known managed folder. Unknown ownership refuses
   removal; another source may still discover the same tool. Start/stop tools, then restart the broker to register a new
   or changed one (the broker reads its registry at startup). You bring the tool's code
   (a process `command`/`app.py`, or a Docker image); the panel writes only the manifest.

Reach it remotely the way you reach the broker: over a tailnet or SSH tunnel, never
by binding a public interface.

## Security

- Binds `127.0.0.1` by default; a non-loopback bind **fails closed** unless
  `TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK=1` (set it only behind a tunnel/proxy you trust, and
  add `TOOLSTACK_ADMIN_SECURE_COOKIE=1` so the session cookie is TLS-only). Mirrors the broker.
- Fail-closed auth: with no password set, the server refuses to start. Scrypt
  password + HMAC-signed session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` when
  `TOOLSTACK_ADMIN_SECURE_COOKIE=1`) + a session-bound **CSRF** token on every POST.
- Login is rate-limited (per-IP + global lockout, shared by the HTML and JSON login) and
  failed attempts are audited (`admin.login_failed` with the IP + attempted username, never
  the password).
- Secrets stay off the browser: the nod token is **write-only / masked**, and tool
  secret *values* are never entered here (tools procure them through SPS);
  the tool editor authors only secret *declarations* (name + field).
- The tool editor writes to a directory you name (operator-trusted, loopback-only); it
  only ever writes a file called `toolyard.toml`, and registers the directory in the
  run-config's `tool_dirs` so the broker discovers it.
- Tokens are shown **once**; the Store keeps only their SHA-256 hash.
- Every mutation (including broker/tool start/stop) is recorded as an `admin.*`
  audit event with the operator's identity, in the same trail `brokerctl` writes.

## Modules

- `__main__.py`: `serve` and `set-password`.
- `server.py`: the FastAPI app: routes, the session + CSRF gate, wiring.
- `views/`: server-rendered HTML (f-strings + `html.escape`, no template engine),
  split by screen: `layout` (page shell + esc/CSRF), `components` (shared fragments),
  `assets` (CSS/JS), and one module each for `login`, `dashboard`, `config`, `tools`,
  and `callers`. `views/__init__.py` re-exports the public surface.
- `auth.py`: scrypt password, HMAC session, CSRF tokens (all stdlib).
- `supervisor.py`: broker process lifecycle (posix_spawn / killpg / `/v1/health`).
- `broker_config.py`: the `BrokerRunConfig` the broker is started from (→ env).
- `toolyard_ops.py`: list / start / stop / restart tools via the toolyard.
- `tool_authoring.py`: build / validate / read / write a tool's `toolyard.toml`.
- `store_access.py`: short-lived broker `Store` connections (WAL makes them coexist
  with the broker's).
- `settings.py`: where login credentials, the session secret, and supervisor state live.

## Test

```bash
admin/.venv/bin/python -m unittest discover -s admin/tests -t .
```

Run from the repo root. The suite covers auth / session / CSRF, the run-config TOML
round-trip, a **real broker** start/stop via the supervisor, the toolyard listing,
tool authoring (build/validate a `toolyard.toml` and confirm the broker registry can
read it), and a full login → create-caller → set-policy flow through FastAPI's
`TestClient`.
## Current operator contracts

The implemented Clear desk web UI uses 38px controls, real HTML selects and
accessible policy labels. Failed loads disable saving; failed saves retain drafts.
Unknown outcomes require fresh read/comparison before retry, never automatic effect
replay. Policy adapters preserve advanced/unavailable grants; the broker's underlying
full-replacement policy semantics are unchanged.

### Catalog, removal and authoring

Public `GET /v1/health` returns `status: ok` and optionally a random opaque
`catalog_observation_id` only: no fingerprint, tool names, paths or secret blocks.
Authenticated `GET /api/catalog` returns `{status: verified, observation_id: <opaque hex>,
tool_ids: [...]}` from the same fingerprint-verified Registry snapshot, including
zero-operation tools, or `{status: unknown}`. An empty list is a valid global
observation but verifies no target. Missing, legacy or malformed membership means
target unknown. Each row/target needs membership in that same receipt;
`/api/tools` discovery is independent and is not registration proof.

Files added, tool Start, and broker registration are separate explicit stages.
Adding never starts a tool or grants authority automatically. Registration proves
neither process liveness nor health. `DELETE /api/tools/{id}` returns
`{removed: id, deleted: false}` for external unregister/files retained and
`deleted: true` for managed-folder deletion. Missing deletion metadata leaves the
filesystem outcome unknown; other duplicate sources may still discover the tool.

OpenAPI imports store authentication in each operation's operator-owned `headers`
and `allowed_secrets`. The tool editor exposes those fields and an optional
`body_template` for a fully operator-owned text body. References such as
`{{secret:api_token}}` are permitted only in these templates and only for that
operation's declared secret allowlist. Never enter actual secret values in the UI.
Caller header values and bodies containing `{{secret:` are rejected with HTTP 400.
`allowed_headers` is only for caller-provided headers and must exclude static
header names. Caller bodies cannot override a body template.

To migrate older tools, move placeholder-bearing headers/body into the operator
templates, fill `allowed_secrets`, remove the static names from `allowed_headers`,
and uncheck legacy caller substitution. Explicit `body_substitution = true` now
fails validation; the default is false. Update caller envelopes to omit the
operator-owned fields. See [REST forwarder](../docs/rest-forwarder.md).
Forwarder refresh operations return status only, without names or value lengths.

At source 855da6e (broker a9319b9 / release059dd13), see [integrated security contracts](../docs/security-contracts.md)
for disclosure and remaining gates. Optional operation approval_fields is preserved
absent versus []; both visibly omit ALL arguments. Pointers explicitly disclose
selected subtrees, not universally safe free text. No UI disclosure controls were
added. The shared validator now rejects '*' anywhere; '/' is a valid empty key,
empty root pointer invalid. Refresh needs ordinary grants; token revocation needs 12–64 lowercase hex.
Policy changes invalidate pending approvals; manifest generation is rechecked at
both immediate/deferred claims (the executing claim is the cancellation commit point).
Schema3 receipts distinguish received/pending_approval/executing/unknown/result_expired,
with idempotency_key/reused/payloads_pruned and wait-timeout broker_status fields;
consumers must adopt them and conflict409 rather than label everything pending.
Matching keys return old receipts even after generation changes, never new effects.
Historical output requires a live current caller/exact presented token and current
allow OR review grant; review is historical read authority, not a new approval.
Deny/removal/revoked token withholds output, not bytes already returned.

Manual prune-payloads/backup/reconcile-offline/restore-new commands are documented
in [security contracts](../docs/security-contracts.md#manual-retention-and-offline-recovery).
Stop ALL broker/admin/CLI writers before confirming offline reconcile/restore;
ordinary Store opening never relabels active work. NEW-destination restore revokes
ALL tokens, clears ALL policies and rotates UUID, never overwrites source or replays.
Keep restored authority revoked until external/post-snapshot history is reconciled;
never blindly replay queues. Seven-day pruning preserves tombstones, not secure
erasure. Native canonical fixture/status adoption is implemented, not full web parity proof.

Password reset rotates the session generation atomically. Running admin instances
reject old browser cookies and bearer tokens on their next request, without a
restart. An already-authorized in-flight action is not cancelled by reset.

Browser sign-out and `POST /api/logout` revoke the presented session on the server.
Sessions have independent random identifiers; revocations persist until expiry.
At the bounded revocation capacity, the signing generation rotates to invalidate
all sessions. Upgrading from the older session format requires signing in again.
The native app calls logout before discarding its client token; an unreachable
server cannot confirm revocation. Accepted HTTP hosts are localhost, loopback
addresses, and the configured admin host.

`GET /api/audit` includes request metadata only, never stored action arguments or
result payloads. Correlation identifiers remain available to native clients.

Configuration audit records changed schema field names, never values, tokens,
paths or destinations. An intent audit must succeed before saving. If completion
auditing fails after saving, the operation fails with an explicit already-saved
error; verify before retrying. Authenticated host administrators can delete the
local audit (HTML also requires session-bound CSRF). Deletion leaves a new
`audit_cleared` marker where storage succeeds, but is not secure erasure or
tamper-proof evidence. A marker-write failure cannot undo the deletion.

Blocking tool import/update, tool lifecycle and broker process control use one
off-loop worker with immediate busy rejection, not an unbounded job queue.
Cancelling a request does not free admission until its actual work ends.
No automatic replay or cancellation of already-running external actions is implied.

Native/API contract fixtures live in `admin/tests/fixtures/native_api.json`.
Backend identity uses `plugin`, not `name`; unknown secret inspection is
`status: UNKNOWN` with `provisioned: null`. Liveness is distinct from recorded
running intent and from health; no health probe means health is unknown, not
healthy. Failed liveness inspection is nullable/unknown. Native strict decoders
adopt these contracts. Old API secret-value provisioning returns 410 and
does not parse or store values; provisioning is host-side only.

Lifecycle mutations require the integrated runner `state_lock` across the
complete load/mutate/save operation. Missing lock support fails closed. A newly
started runtime is stopped if its record cannot be published; failed cleanup
returns explicit failure and retains a runtime reference for recovery. State
and channel-view publication are not a single filesystem transaction.

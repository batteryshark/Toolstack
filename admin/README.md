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
   unregisters a panel-added tool (stops it and drops it from the broker's search path;
   its files stay on disk). Start/stop tools, then restart the broker to register a new
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
  secret *values* are never entered here (the toolyard resolves them from the on-disk
  secrets file); the tool editor authors only secret *declarations* (name + field).
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

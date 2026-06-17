# Deploying Toolstack

This directory holds the operator-facing deployment artifacts for a real (homelab /
single-host) install. It deploys the **admin web app**, which in turn supervises the
**broker**; the toolyard and tools run as the admin app starts them.

| File | What it is |
|---|---|
| [`toolstack-admin.service`](toolstack-admin.service) | systemd unit **template** for the admin panel (+ the broker it supervises). Ships with placeholders — copy and edit, don't symlink. |
| [`toolstack-admin.env.example`](toolstack-admin.env.example) | example `EnvironmentFile` — the site config (secret backend, Infisical host/vault, toolyard runner). Copy, fill in, `chmod 600`. |
| [`redeploy-toolstack`](redeploy-toolstack) | one command to pull + refresh the venv + restart the service + restart registered tools. |

The broker, toolyard, and client are stdlib-only Python (3.11+). The **admin app is the
one component with runtime dependencies** (FastAPI + uvicorn), so it runs from its own
virtualenv. See [admin/README.md](../admin/README.md) for what the panel does.

## Prerequisites

- **Python 3.11+** (the broker/toolyard use `tomllib`).
- An **admin virtualenv** with the panel's deps: `python3 -m venv admin/.venv && admin/.venv/bin/pip install -r admin/requirements.txt`. (`redeploy-toolstack` creates/refreshes this for you.)
- A **secret backend**: the dev `file` backend (a local `secrets.toml`) or **Infisical** (set the `TOOLSTACK_INFISICAL_*` vars — see the env example).
- For production tool isolation: **Docker** (`TOOLSTACK_RUNNER=docker`). The `process` runner is dev-only.
- For human approvals: a reachable **[nod](https://github.com/batteryshark/nod)** instance and an issuer token — configured from the dashboard, not this env file (see "Broker config" below).

## Install

1. **Lay down the code** at your install root (the examples assume `/opt/toolstack/TSR`, owned by a `toolstack` user — change to taste) and build the admin venv (above).
2. **Set the admin password** (the panel fails closed — it refuses to start without one):
   ```bash
   admin/.venv/bin/python -m admin set-password
   ```
3. **Site config** — copy and fill in the env file, then lock it down (it can hold an Infisical host / paths):
   ```bash
   sudo install -D -m600 deploy/toolstack-admin.env.example /etc/toolstack/admin.env
   sudoedit /etc/toolstack/admin.env
   ```
4. **Install the unit** — copy the template and edit every line marked `EDIT:` (the service account and the install root, which repeats in `WorkingDirectory` + the three `Exec` lines):
   ```bash
   sudo cp deploy/toolstack-admin.service /etc/systemd/system/toolstack-admin.service
   sudoedit /etc/systemd/system/toolstack-admin.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now toolstack-admin
   ```
5. **Reach the panel** over a tunnel that terminates TLS (Tailscale Serve, SSH, etc.) — it binds `127.0.0.1` only and has no TLS of its own. Never bind it to a public interface.

The broker's own run-config (its port, DB path, the nod URL/token/channel, approval TTL,
rate limit) is **not** in the env file — the admin app stores it in `broker.toml` and you
edit it from the dashboard's **Config** page. (`admin/broker_config.py` is the source of truth.)

## Supervision model (why `ExecStartPost`, and why it's not an orphan bug)

`ExecStart` runs the **admin panel** — the long-lived, systemd-tracked process. The
**broker is not a child of it**. It is supervised out of band by a state file (PID + port
under the admin XDG state dir), exactly like the toolyard's `ProcessRunner`: it runs in its
own process group, started and stopped through `admin.supervisor`. `ExecStartPost`
auto-starts it on boot (idempotent — it no-ops if a healthy broker is already recorded) and
`ExecStopPost` tears it down; init reaps it. You can also start/stop/restart it from the
dashboard.

**Trade-off:** because systemd doesn't track the broker, a broker *crash* won't trigger a
systemd restart on its own — the dashboard surfaces broker health, and the unit's
`Restart=on-failure` only covers the panel. If you'd rather systemd own the broker directly,
run `python -m broker.server` as its own unit (with the same `EnvironmentFile`) and drop the
`ExecStartPost`/`ExecStopPost` lines.

## Redeploying

From anywhere in the checkout:

```bash
deploy/redeploy-toolstack [--pull] [--skip-venv] [--skip-service] [--skip-tools]
```

It optionally fast-forwards git, refreshes the admin venv, restarts the service (admin +
broker), and restarts every tool in the saved run-config. It loads the same site env as the
unit (`TOOLSTACK_ENV_FILE`, default `/etc/toolstack/admin.env`) so the tool restarts use the
deployment's runner / secret backend.

## Verify

```bash
systemctl status toolstack-admin           # the panel is active (running)
curl -s 127.0.0.1:8765/v1/health           # the broker -> {"status":"ok"}
curl -s 127.0.0.1:8780/login -o /dev/null -w '%{http_code}\n'   # the panel -> 200
```
Then open the dashboard: the broker card shows healthy, and the audit view fills as
requests flow.

## Upgrading from an earlier install (migration note)

Older units set `XDG_STATE_HOME=…/tsr`; the template drops that and uses the app's default
(`~/.local/state/toolstack/…`). If a previous run already saved `broker.toml`, its stored
`db_path` still points at the **old** location — admin and broker stay consistent (both read
`broker.toml`), so it isn't data loss, just a different SQLite file than a fresh install
would pick. To move to the new default, update `db_path` on the dashboard Config page (or
delete `broker.toml` to regenerate it) and migrate the SQLite file if you want the history.
There is no DB-migration framework — assume a fresh DB on a major upgrade.

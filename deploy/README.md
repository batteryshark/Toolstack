# Deploying Toolstack

This directory holds the operator-facing deployment artifacts for a real (homelab /
single-host) install via **systemd**. It deploys the **admin web app**, which in turn
supervises the **broker**; the toolyard and tools run as the admin app starts them.

> **On a laptop?** For a self-contained, no-server install, use the one-box Docker setup
> instead: [`docker/`](docker/); `docker compose up` brings up the whole stack with an
> encrypted local vault. See [docker/README.md](docker/README.md).

| File | What it is |
|---|---|
| [`toolstack-admin.service`](toolstack-admin.service) | systemd unit **template** for the admin panel (+ the broker it supervises). Ships with placeholders; copy and edit, don't symlink. |
| [`toolstack-admin.env.example`](toolstack-admin.env.example) | example `EnvironmentFile`: the site config (secret backend, Infisical host/vault, toolyard runner). Copy, fill in, `chmod 600`. |
| [`redeploy-toolstack`](redeploy-toolstack) | one command to pull + refresh the venv + restart the service + restart registered tools. |

The broker, toolyard, and client are stdlib-only Python (3.11+). The **admin app is the
one component with runtime dependencies** (FastAPI + uvicorn), so it runs from its own
virtualenv. See [admin/README.md](../admin/README.md) for what the panel does.

## Prerequisites

- **Python 3.11+** (the broker/toolyard use `tomllib`).
- An **admin virtualenv** with the panel's deps: `python3 -m venv admin/.venv && admin/.venv/bin/pip install -r admin/requirements.txt`. (`redeploy-toolstack` creates/refreshes this for you.)
- A **secret backend**: the dev `file` backend (a local `secrets.toml`) or **Infisical** (set the `TOOLSTACK_INFISICAL_*` vars, see the env example).
- For production tool isolation: **Docker** (`TOOLSTACK_RUNNER=docker`). The `process` runner is dev-only.
- For human approvals: a reachable **[nod](https://github.com/batteryshark/nod)** instance and an issuer token, configured from the dashboard, not this env file (see "Broker config" below).

## Install

1. **Lay down the code** at your install root (the examples assume `/opt/toolstack`, owned by a `toolstack` user, change to taste) and build the admin venv (above).
2. **Create the state dir and set the admin password** (the panel fails closed; it refuses to start without one). The service keeps everything it writes under `/var/lib/toolstack` (the unit's `StateDirectory` owns it); create it now so the password lands where the service will read it:
   ```bash
   sudo install -d -o toolstack -g toolstack -m700 /var/lib/toolstack
   sudo -u toolstack env XDG_CONFIG_HOME=/var/lib XDG_STATE_HOME=/var/lib \
       admin/.venv/bin/python -m admin set-password
   ```
   The `XDG_*` values match the unit (see its "State location" block); every manual `admin` / `brokerctl` command needs them so it resolves the same paths as the running service.
3. **Site config**: copy and fill in the env file, then lock it down (it can hold an Infisical host / paths):
   ```bash
   sudo install -D -m600 deploy/toolstack-admin.env.example /etc/toolstack/admin.env
   sudoedit /etc/toolstack/admin.env
   ```
4. **Install the unit**: copy the template and edit every line marked `EDIT:` (the service account and the install root, which repeats in `WorkingDirectory` + the three `Exec` lines):
   ```bash
   sudo cp deploy/toolstack-admin.service /etc/systemd/system/toolstack-admin.service
   sudoedit /etc/systemd/system/toolstack-admin.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now toolstack-admin
   ```
5. **Reach the panel** over a tunnel that terminates TLS (Tailscale Serve, SSH, etc.); it binds `127.0.0.1` only and has no TLS of its own. Never bind it to a public interface.

The broker's own run-config (its port, DB path, the nod URL/token/channel, approval TTL,
rate limit) is **not** in the env file; the admin app stores it in `broker.toml` and you
edit it from the dashboard's **Config** page. (`admin/broker_config.py` is the source of truth.)

## Supervision model (why `ExecStartPost`, and why it's not an orphan bug)

`ExecStart` runs the **admin panel**, the long-lived, systemd-tracked process. The
**broker is not a child of it**. It is supervised out of band by a state file (PID + port
under the admin XDG state dir), exactly like the toolyard's `ProcessRunner`: it runs in its
own process group, started and stopped through `admin.supervisor`. `ExecStartPost`
auto-starts it on boot (idempotent: it no-ops if a healthy broker is already recorded) and
`ExecStopPost` tears it down; init reaps it. You can also start/stop/restart it from the
dashboard.

**Trade-off:** because systemd doesn't track the broker, a broker *crash* won't trigger a
systemd restart on its own; the dashboard surfaces broker health, and the unit's
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

Two safety steps wrap the restart: it **snapshots the broker DB** first (an online SQLite
backup under `.../broker/backups/`, newest 7 kept) and then **health-gates** the broker
(`/v1/health`) and panel (`/login`). If the stack doesn't come back up it stops there
rather than restarting tools against a down broker. Run it as the `toolstack` user (it
reads the broker's state and DB directly); `sudo` is used only for `systemctl`.

## Verify

```bash
systemctl status toolstack-admin           # the panel is active (running)
curl -s 127.0.0.1:8765/v1/health           # the broker -> {"status":"ok"}
curl -s 127.0.0.1:8780/login -o /dev/null -w '%{http_code}\n'   # the panel -> 200
```
Then open the dashboard: the broker card shows healthy, and the audit view fills as
requests flow.

## First run: provision an agent (headless)

The dashboard can do all of this, but a fresh box can be bootstrapped entirely from the
CLI. `brokerctl` is the operator tool; run it as the service user with the same `XDG_*`
paths as the unit so it opens the broker's DB (define a small helper to avoid repeating it):

```bash
ctl() { sudo -u toolstack env XDG_CONFIG_HOME=/var/lib XDG_STATE_HOME=/var/lib \
    admin/.venv/bin/brokerctl "$@"; }

ctl create-caller --name my-agent --allow echo_api.echo   # the agent identity + an initial grant
ctl set-policy   --name my-agent --review some_tool.write # (optional) route an op through approval
ctl issue-token  --name my-agent                          # prints the bearer token; copy it once
```

Give the token to the agent as its `Authorization: Bearer ...`. Tighten or widen access later
with `set-policy` (`--allow` / `--review` / `--deny`, path-scoped for `rest` tools), and
rotate with `revoke-token` / `issue-token`. (`ctl` uses the broker's default DB path; if you
changed `db_path` in `broker.toml`, pass `--db <path>`.)

## Backups

Everything persistent lives under the state dir (`/var/lib/toolstack`). Two things are worth
backing up off-box:

- **Broker SQLite** (`/var/lib/toolstack/broker/broker.sqlite3`): callers, tokens, policies,
  request history, audit log. Take a *consistent* copy while the broker runs with SQLite's
  online backup (`redeploy-toolstack` does this automatically before each restart):
  ```bash
  sudo -u toolstack sqlite3 /var/lib/toolstack/broker/broker.sqlite3 \
      ".backup '/var/lib/toolstack/broker/backups/manual-$(date +%F).sqlite3'"
  ```
- **Config + secrets**: `broker.toml` (run-config; holds the nod issuer token) and, with the
  encrypted-vault backend, `vault.json` (both under `/var/lib/toolstack/admin/` and
  `/var/lib/toolstack/`). The vault is useless without its passphrase; store that separately.

Restore is a file copy back into place with the service stopped. There is no DB-migration
framework; restore into the same (or a forward-compatible) version.

## Upgrading from an earlier install (state location)

This template pins all state under `/var/lib/toolstack` (`StateDirectory` + `XDG_*_HOME=/var/lib`).
Earlier templates relied on the service user's `$HOME` (`~/.local/state/toolstack/...`, or an
even older `.../tsr` path). Admin and broker both read `db_path` from `broker.toml`, so an
upgrade isn't data loss; it just points at a different SQLite file than the old `$HOME` one.
To keep your history, stop the service, move the old DB to
`/var/lib/toolstack/broker/broker.sqlite3` (and the old `broker.toml` / `vault.json` under
`/var/lib/toolstack/`), then start it. Or update `db_path` on the dashboard **Config** page to
point at wherever the old DB lives. No DB-migration framework; assume a fresh DB across a
major upgrade if you don't migrate.

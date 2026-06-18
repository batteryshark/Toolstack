# Toolstack one-box (Docker, for a laptop)

Run the whole stack — broker + admin + toolyard — in a single container on your laptop,
no home-lab server and no external secret service required. State persists in `./data`.

This is the **laptop** path. For a server install, see [../README.md](../README.md) (systemd).

## What's in the box

One image runs `python -m admin serve`. The admin (a loopback web UI) supervises the
**broker** as a subprocess and runs **tools** with the **process runner** — so the broker
and tools share one container loopback. (Tools run as processes, not nested containers:
docker-out-of-docker would publish tool ports to the host loopback, which the in-container
broker couldn't reach. Less isolation, but correct and simple for one user.)

Secrets use the **encrypted vault** ([T-025](../../toolyard/secrets.py)) by default — a
local file encrypted with your passphrase. The broker never sees a secret.

## Quick start

```bash
cd deploy/docker
cp .env.example .env
# edit .env: set TOOLSTACK_ADMIN_PASSWORD and TOOLSTACK_VAULT_PASSPHRASE
docker compose up -d --build
```

Then:

1. Open the admin UI at **http://127.0.0.1:8780** and log in (user `admin`, your password).
2. Click **Start broker**. It comes up on `127.0.0.1:8765`.
3. **Add a caller** and mint a token (this is your agent's bearer token).
4. **Author a tool** (or use the bundled `echo`), grant the caller an op (allow / review).
5. Point your agent at the broker: `TOOLSTACK_URL=http://127.0.0.1:8765`,
   `TOOLSTACK_TOKEN=<the token>` — REST, or the broker-native MCP at `POST /mcp`.

Provision a tool's secret into the vault from inside the box:

```bash
docker compose exec toolstack sh -c 'printf "%s" "the-secret" | toolyard vault-set <tool> <FIELD>'
```

## The trust boundary (important)

Inside the container the broker and admin bind `0.0.0.0` so Docker can reach them. The
boundary is the **publish mapping**: compose publishes both ports to `127.0.0.1` on the
host *only*. Do not change the host side to `0.0.0.0` — that would expose the broker /
admin on your network. (This mirrors how tool containers already bind `0.0.0.0` + publish
to host loopback via `TOOLSTACK_BIND`.)

> ⚠️ If you bypass compose and use `docker run`, you **must** prefix every `-p` with
> `127.0.0.1:` — e.g. `-p 127.0.0.1:8765:8765`. A bare `-p 8765:8765` defaults to
> publishing on **all** interfaces (`0.0.0.0`), exposing the broker (bearer-token-only) and
> the admin on your LAN. The compose file already does this correctly; the trap is only on
> hand-written `docker run`.

## State & lifecycle

Everything lives under `./data` (mounted at `/data`): admin config (password hash,
session key, broker config), the broker SQLite DB + audit, the encrypted vault, and
toolyard state. Back up `./data` to back up your whole setup. `docker compose down`
stops the box but keeps `./data`; delete `./data` to start fresh.

## Adding your own tools

Author tools into a directory under the volume (e.g. `/data/tools/<id>/`) so they
persist, then add that directory in the admin's **broker config** (tool dirs). A process
tool needs its code present in that directory; the panel writes its `toolyard.toml`.

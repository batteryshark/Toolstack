# Deploying Toolstack

This directory contains the systemd templates and helper scripts for a single-host
Toolstack deployment. The admin service supervises the broker and manages tools; the
reconcile service restores tools recorded as running after boot.

| File | Purpose |
|---|---|
| [`toolstack-admin.service`](toolstack-admin.service) | Admin panel and broker supervision template |
| [`toolstack-tools.service`](toolstack-tools.service) | Boot-time tool reconciliation template |
| [`toolstack-admin.env.example`](toolstack-admin.env.example) | Non-secret site configuration |
| [`redeploy-toolstack`](redeploy-toolstack) | Update, restart, and health-check the deployment |

For a self-contained laptop install, see [`docker/`](docker/).

## Prerequisites

- Python 3.11+
- A dedicated service account such as `toolstack`
- Docker for production tool isolation
- An Infisical project with one machine identity and access policy per tool
- Optional: nod for human approval workflows

The service account needs access to the Docker socket. Add it to the `docker` group or
uncomment `SupplementaryGroups=docker` in both unit files.

## Install

From the checkout, the installer creates the service account, virtual environment,
password, and systemd unit:

```bash
sudo deploy/install.sh
```

For a manual install, the templates assume `/opt/toolstack` and a `toolstack` service
account:

```bash
python3 -m venv admin/.venv
admin/.venv/bin/pip install -e '.[vault]' -r admin/requirements.txt

sudo install -d -o toolstack -g toolstack -m700 /var/lib/toolstack
sudo -u toolstack env XDG_CONFIG_HOME=/var/lib XDG_STATE_HOME=/var/lib \
    admin/.venv/bin/python -m admin set-password

sudo install -D -m600 deploy/toolstack-admin.env.example /etc/toolstack/admin.env
sudo cp deploy/toolstack-admin.service deploy/toolstack-tools.service /etc/systemd/system/
sudoedit /etc/toolstack/admin.env
sudoedit /etc/systemd/system/toolstack-admin.service
sudoedit /etc/systemd/system/toolstack-tools.service
sudo systemctl daemon-reload
sudo systemctl enable --now toolstack-admin toolstack-tools
```

Edit every `EDIT:` line in both units. Their account, checkout path, environment file,
and XDG state settings must match.

## Infisical Identities

Each tool authenticates with its own Infisical machine identity. Its identity should be
authorized only for that tool's secret path, with write permission limited to fields the
tool may rotate.

Do not place machine-identity client secrets in `admin.env`. On systemd, encrypt each
identity with `systemd-creds` and load it through `LoadCredentialEncrypted`. Build the
plaintext input under `/dev/shm` so it never touches persistent storage:

```bash
sudo install -d -m700 /etc/credstore.encrypted/toolstack-infisical
install -d -m700 /dev/shm/toolstack-credentials

$EDITOR /dev/shm/toolstack-credentials/spotify-tool.env
sudo systemd-creds encrypt --with-key=tpm2 --name=infisical_spotify-tool.env \
    /dev/shm/toolstack-credentials/spotify-tool.env \
    /etc/credstore.encrypted/toolstack-infisical/spotify-tool.env
rm /dev/shm/toolstack-credentials/spotify-tool.env
```

The input file contains:

```text
INFISICAL_CLIENT_ID=...
INFISICAL_CLIENT_SECRET=...
```

Repeat for each secret path, then uncomment these lines in both units:

```ini
LoadCredentialEncrypted=infisical:/etc/credstore.encrypted/toolstack-infisical
Environment=TOOLSTACK_INFISICAL_CREDENTIALS_DIR=%d
Environment=TOOLSTACK_INFISICAL_CREDENTIAL_PREFIX=infisical_
```

At runtime, systemd unseals the identities into a read-only, non-swappable credential
directory visible only to the service account. TPM sealing avoids keeping the decryption
key beside the encrypted blobs. On a host without a TPM, use another operator-mediated or
hardware-backed bootstrap rather than placing client secrets in `admin.env`. Toolyard
selects `<secret-path>.env` for the tool it is starting. A single identity in the process
environment remains available only as a development fallback.

## Secret Transport

For Docker tools, Toolyard resolves secrets into memory, starts the container behind an
initialization gate, and streams each value over Docker stdin into a private
`/run/secrets` tmpfs. The application command starts only after injection succeeds.
Values never enter a host file, bind mount, container layer, environment variable,
command argument, or Docker metadata.

Writable secret rotations use the per-tool `/run/toolyard/secrets.sock` channel.
Toolyard validates the declared writable field and updates Infisical with that tool's
machine identity. Backend credentials are never mounted into the tool container.

The host must not enable swap because tmpfs and process memory can otherwise be written
to disk. Toolyard checks this before resolving a value and fails closed. The service
templates also create `/run/toolyard` for runtime sockets
and dev-runner files; `/run` is tmpfs and is cleared at boot.

## Reconciliation

`toolstack-tools.service` runs after Docker and the admin service. It checks the
non-secret injection marker inside each recorded container and restarts only tools whose
process or ephemeral secrets are missing. Tools absent from state remain stopped.

```bash
sudo systemctl restart toolstack-tools
sudo systemctl status toolstack-tools
```

Verify the deployment once after a real reboot and confirm each registered tool's health
endpoint returns 200.

## Network Exposure

The admin panel and broker bind to loopback. Reach them through a trusted TLS-terminating
tunnel such as Tailscale Serve or SSH. Do not publish either service directly to the
internet.

## Redeploying

```bash
deploy/redeploy-toolstack [--pull] [--skip-venv] [--skip-service] [--skip-tools]
```

The script can fast-forward the checkout, refresh the virtual environment, snapshot the
broker database, restart services and registered tools, and health-check the broker and
panel.

## Verify

```bash
systemctl status toolstack-admin toolstack-tools
curl -fsS 127.0.0.1:8765/v1/health
curl -fsS 127.0.0.1:8780/login -o /dev/null
docker ps --filter name=toolyard-
```

Persistent state lives under `/var/lib/toolstack`. Back up the broker SQLite database,
`broker.toml`, and any encrypted local vault in use. Infisical remains the source of truth
for production tool secrets.

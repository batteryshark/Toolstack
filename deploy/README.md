# Deployment (trusted host only)

See [runtime matrix](../docs/runtime-matrix.md). Source templates are not evidence
of a deployed, hardened installation. No privileged mutable Python helper is supported.
Release use requires a dedicated Toolstack VM containing only Toolstack and trusted
tools under its account. Agents must remain outside the host with broker-only access.
Same-machine/account agents are local/dev only and do not isolate secrets.

## Native Linux recipe

Python 3.11+ and OpenSSL are required. Review `install.sh` before executing as root:
it creates an account, changes checkout ownership, installs into a dedicated venv,
sets a password interactively and enables services. These templates have **not** been installed or run in the reported validation.
Only trusted process tools may run under the shared service account. Do not add
sudoers permissions for `toolyard.netguard`, Docker group membership, or remove
`NoNewPrivileges=true` to work around unsupported backends.

`uv.lock` is authoritative. `admin/requirements-lock.txt` is its complete deployment
export, used as requirements AND constraints by install, redeploy and Docker builds.
The vault dependency is `cryptography>=50.0.2,<51`, locked to **50.0.2**.
Use the current lock and minimum fixed line, not the obsolete 45.x / `<46` range;
see [dependency evidence and limits](../docs/security-contracts.md#dependency-and-validation-evidence).
Regenerate using the command in `admin/requirements.txt`. Install is non-editable;
admin runs from the checkout under systemd, while the installed wheel must also work
without that checkout. Redeploy updates both; stop workloads first for upgrades.

## SPS bootstrap (offline)

`sps.env` is TOML despite its suffix; never source it or load it as a systemd
EnvironmentFile. `/etc/toolstack/sps-runtime.env` is a separate, mode-0600 systemd
file for `SP_VAULT_PASSPHRASE` (use a fake value in development). The installer
creates `/etc/toolstack`; unprivileged users must not try to create it themselves.

After install, before enabling SPS for the first time, as root:

```sh
umask 077
/opt/toolstack/admin/.venv/bin/python /opt/toolstack/deploy/bootstrap-sps.py
chown toolstack:toolstack /etc/toolstack/sps.env /etc/toolstack/sps.key
chown toolstack:toolstack /etc/toolstack/sps.crt /etc/toolstack/sps-ca.crt
```

Adjust account and install root to match the installer. Bootstrap creates only TLS
material/config, not a vault. Vault lives in `/var/lib/toolstack/sps.vault.json`,
audit in `/var/lib/toolstack/audit/sps.audit` (not under `/var/log`: SPS refuses group-writable ancestors and Ubuntu keeps `/var/log` group-writable; existing installs should point `SP_AUDIT_LOG` there); `/etc` remains read-only in the services.
Provision `sps init-vault` and `sps vault-set` as the service user with the venv,
explicit `--config /etc/toolstack/sps.env`, and the same passphrase as the SPS
runtime file. Keep SPS **stopped during all direct provisioning**. Never put real
values on command lines, in git, or in shell history. Restrict runtime-file ownership
to root and mode 0600; systemd reads it before dropping privileges.

Set `TOOLSTACK_SPS_ENV=/etc/toolstack/sps.env` in admin.env if required by the
resolved runner configuration (see SPS docs); use verified TLS and explicit CA path.
Verify the runner's resolved SPS configuration and CA path before deployment.
Start SPS, then admin; check journal and health before launching trusted tools.
Private umask/directories do not isolate processes sharing the same uid.

## Updates, backup and restore

`redeploy-toolstack` snapshots SQLite with the SQLite backup API before restarting
services (seven snapshots retained). These contain sensitive arguments/results;
directories are private and copies need equivalent protection. A SQLite snapshot
alone is NOT a complete installation backup. Back up config, TLS, encrypted vault,
its separately protected passphrase, tool manifests and application version as a
consistent offline set after stopping tools/admin/SPS. Do not copy a live SQLite
file without its WAL; use the backup API or stop all writers first.

Broker schema 3 includes caller-scoped receipts, manual retention and offline recovery.
Use explicit private paths (examples below are placeholders), with the installed
version's Python environment. See the [complete maintenance contract](../docs/security-contracts.md#manual-retention-and-offline-recovery):

```sh
python3 -m broker.brokerctl prune-payloads --db /private/state/broker.db
python3 -m broker.brokerctl backup --db /private/state/broker.db --destination /private/backups/snapshot.db
```

Pruning is manual: terminal payloads must be **strictly older than seven days**.
Caller/key/digest tombstones remain; active work is not pruned. WAL and backups can
retain bytes, so this is not secure erasure. Backup uses SQLite's backup API,
including committed WAL, and publishes only to a **NEW destination**.

**Stop ALL broker/admin/CLI writers** before either offline command:

```sh
python3 -m broker.brokerctl reconcile-offline --db /private/state/broker.db --confirm-offline
python3 -m broker.brokerctl restore-new --snapshot /private/backups/snapshot.db --destination /private/recovery/new.db --confirm-offline
```

Confirmation asserts offline operation; it does not detect or stop writers.
Reconcile marks received/executing work unknown without replay. Restore cancels
pending approvals, marks received/executing work unknown, revokes **ALL tokens**,
clears **ALL policies**, and rotates the installation UUID. Source DB and backup
are never overwritten; restore neither switches the running DB nor replays effects.
Post-snapshot keys/effects are unknown to a stale backup: reconcile external history
before restoring authority or replaying queues. Reissuing tokens alone restores no
grants. Broker recovery does not restore SPS/provider state; test the complete
offline backup set with fake data before operational use.

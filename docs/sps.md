# SPS — Secrets Procurement Service

SPS authorizes a registered tool's declared secret names and writable mappings.
The runner registers using SP_SECRET (broad authority); each tool receives an
E_SECRET capability for its registration. Broker channel credentials must be
separate from SPS capabilities: runner independently randomizes them and broker
reads dedicated channels.json without E_SECRET/private-state fallback. Trusted
same-account host processes still have file/memory access. See
[exact current bounds and pending gates](security-contracts.md).

## Protocol and storage

One JSON line in/out over verified TLS/TCP, not HTTP. Localfile uses scrypt and
Fernet authenticated encryption at rest. SPS decrypts values into memory and tools
cache plaintext. TLS protects transport, not endpoint memory. Registrations are
volatile; SPS restart needs runner re-registration and failed-recovery retries.
Revocation does not erase already cached values.

Supported release: dedicated Toolstack VM containing only Toolstack and trusted
tools under its account, agents outside the host reaching only the broker.
Same-machine/account agents are local/dev only; this is not hostile-code isolation.
See [matrix](runtime-matrix.md) for unsupported Docker/Seatbelt/native-helper paths.

## Bootstrap and provision

Use [deployment bootstrap](../deploy/README.md): `/etc/toolstack/sps.env` is private
TOML, not a shell/systemd env file. The deployment wrapper passes `sps init`
`--state-dir /var/lib/toolstack --audit-log /var/log/toolstack/sps.audit`.
Choose dedicated private immediate parents for vault, audit and boot identity;
unsafe existing paths are refused, never repaired by blind chmod. New nested
parents are 0700, vault/audit/lock 0600, nonsecret boot identity 0644 under its
private parent. Do not blindly chmod shared directories. TLS files/config remain under
`/etc`; writable vault/audit do not. For local fake tests supply temporary paths
instead. Never create `/etc` unprivileged, disable TLS verification, or commit values.

The localfile passphrase comes from `SP_VAULT_PASSPHRASE` or supported `_FILE`
configuration. systemd runtime env is separate `/etc/toolstack/sps-runtime.env`.
Use the same passphrase for offline provisioning and server startup. With SPS
**stopped**, initialize the vault and provision using the venv commands:

```sh
sps init-vault --config /path/to/private/sps.env
printf '%s\n' fake-only | sps vault-set --config /path/to/private/sps.env demo API_KEY
sps vault-get --config /path/to/private/sps.env demo API_KEY
```

`vault-get` reports presence, not the value. Do not directly provision a running
localfile backend as an operational precaution. Cooperating writers now lock and
reload; noncooperating writers remain unsafe. Runtime tool writes
use SPS writeback and require explicit writable grants. Response redaction is a
separate concern; storing a returned token does not automatically hide the response.

## Providers and operations

Plugins: `localfile`, `infisical`, `hashicorp_vault`; select exactly one at startup.
Real providers are not contacted by release tests. Provider-specific correctness
and write semantics require their own tests, not assumptions from plugin presence.
Use HTTPS and verified CA configuration for remote providers.

SPS audit is local operational evidence, not tamper-proof and not a guarantee that
every malformed/rejected request is recorded. Keep audit values out of logs and
protect copies. Rejected credentials, unavailable backend, failed verification or
missing registration must be diagnosed without logging secret material.

On restart, check SPS readiness then runner recovery before invoking tools. A
`Not found` can mean absent registration or missing declared name; it is not proof
the underlying provider value is absent. TLS errors mean check CA/SAN/readability,
not opt out of verification.

Broker schema3 receipts, manual seven-day terminal-payload pruning and private
NEW-destination SQLite backup/restore are integrated at855da6e (release059dd13).
See [exact operator commands](security-contracts.md#manual-retention-and-offline-recovery).
These affect broker state, **not** the SPS vault/provider/cache. Broker restore
revokes all tokens, clears all policies and rotates installation UUID; it does not
roll back workload/provider effects. Stop ALL broker/admin/CLI writers before
offline reconcile/restore and explicitly reconcile external history, including
effects after a stale snapshot. Never blindly replay old agent queues. Pruning
is not secure erasure from WAL/backups; backend backup remains separate.

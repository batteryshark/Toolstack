# SPS — Secrets Procurement Service

SPS authorizes a registered tool's declared secret names and writable mappings.
The runner registers using SP_SECRET, subject to SPS's item grant policy; each tool receives an
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

By default a registration can bind only its own tool id as the backend `item`
(omitting `item` has the same meaning). To authorize a shared item or provider
path, add an explicit allowlist to the private TOML configuration:

```toml
[grants]
my_tool = ["shared-service", "team/provider-path"]
```

These entries supplement the tool's own item; they are exact strings, not globs.
Unlisted cross-tool items return `Unauthorized`. Existing registrations remain
in memory until replaced, removed or SPS restarts; config is loaded at startup.
Keep the `[grants]` table after top-level settings and outside plugin tables.
SPS still trusts the registrar to choose fields and writable entries within
allowed items.

Supported release: dedicated Toolstack VM containing only Toolstack and trusted
tools under its account, agents outside the host reaching only the broker.
Same-machine/account agents are local/dev only; this is not hostile-code isolation.
See [matrix](runtime-matrix.md) for unsupported Docker/Seatbelt/native-helper paths.

## Bootstrap and provision

Use [deployment bootstrap](../deploy/README.md): `/etc/toolstack/sps.env` is private
TOML, not a shell/systemd env file. The deployment wrapper passes `sps init`
`--state-dir /var/lib/toolstack --audit-log /var/lib/toolstack/audit/sps.audit`.
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

Both provisioning commands accept `SP_VAULT_PASSPHRASE_FILE` as well as the direct
environment value (the direct value takes precedence for these commands and the
runtime plugin). New vaults use scrypt N=65536, r=8, p=1 with a 128 MiB memory
ceiling. Existing vaults retain their stored parameters on reads and writes.
`init-vault --force` destroys existing contents; it is not an in-place re-key.

## Providers and operations

Plugins: `localfile`, `infisical`, `hashicorp_vault`; select exactly one at startup.
Real providers are not contacted by release tests. Provider-specific correctness
and write semantics require their own tests, not assumptions from plugin presence.
Use HTTPS and verified CA configuration for remote providers.

SPS audit is local operational evidence, not tamper-proof and not a guarantee that
every malformed/rejected request is recorded. Keep audit values out of logs and
protect copies. Rejected credentials, unavailable backend, failed verification or
missing registration must be diagnosed without logging secret material.

Successful registrations record hashed field/item pairs, entry count and writable
count. Ping, malformed requests and failed authentication use constant-space,
rate-bounded counters rather than individual audit lines. Summaries flush at most
once per second (up to four counter categories); they are best effort. Audit
rotation retains five generations of up to 4 MiB each plus the current file.

TLS handshakes and request bodies have separate absolute five-second deadlines.
Writes above 65536 UTF-8 bytes return `Bad request` before reaching the provider;
set top-level `SP_MAX_VALUE_BYTES` to a positive TOML integer to change the limit.
The wire's 1 MiB request limit still applies. Non-loopback `SP_HOST` requires
explicit top-level `SP_ALLOW_NONLOOPBACK = "1"`; loopback remains the default.
New self-signed loopback certificates last ten years; startup warns when fewer
than 30 days remain. Existing certificates are not changed automatically. Use
`regen-tls`, restart SPS, and redistribute the new CA to clients when rotating.
The SDK's fake test path refuses to run whenever `TOOLSTACK_E_SECRET` is present.

On restart, check SPS readiness then runner recovery before invoking tools. A
`Unauthorized` covers both missing registration and a wrong E_SECRET. `Not found`
means an authenticated caller requested an undeclared name; it is not proof
the underlying provider value is absent. Provider failures return `Backend error`,
including failures during bulk reads. TLS errors mean check CA/SAN/readability,
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

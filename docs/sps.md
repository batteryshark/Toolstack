# SPS — Secrets Procurement Service

The SPS mediates secrets between tool runners / tools and the underlying
backend. It is the single authority boundary for secret retrieval and
update — the broker holds no backend credential and never sees a secret
value.

## What it is and isn't

| ✓ SPS does | ✗ SPS does not |
|---|---|
| Speak TLS/TCP to runners + tools (auth: `spsecret` / `esecret` body fields) | Speak HTTPS REST, persistent connections, or anything other than one JSON line per direction per connection |
| Hold encrypted values in memory at most (no persistence across restart) | Persist tools / registrations across restart; the in-memory pool is *intentionally* lost on crash to force re-registration |
| Audit-log every call (tool_id, action, secret_name, ts) | Log workload-secret values, SP_SECRET, or E_SECRET |
| Cap request bodies at 1 MiB; enforce per-connection timeout | Stream or chunk |
| Plug into one provider plugin at startup (Infisical / Hashicorp Vault / localfile) | Hot-swap plugins, multi-backend fan-out |

The wire protocol is intentionally minimal: no HTTP methods, paths, headers,
ALPN, request IDs. JSON-line framing is the entire message boundary.
See [message-contracts.md §3](message-contracts.md#3-tool--sps-read-and-update)
for the full client-side contract.

## Running SPS

### Bootstrap (first boot)

```bash
python3 -m sps.cli init --config /etc/toolstack/sps.env
```

This generates a starter `sps.env` (mode 0600), a fresh 64-hex `SP_SECRET`,
and self-signed cert / key / CA bundle. Idempotent — refuses to overwrite an
existing `sps.env`.

### Production deploy

`sps` is its own systemd unit (`deploy/toolstack-sps.service`). The unit
points at `/etc/toolstack/sps.env`; key signals:

- `User=toolstack`, mode 0600 enforced at SPS startup (immediate `Unauthorized` if not).
- `ReadWritePaths=/var/lib/toolstack /var/log/toolstack` for the audit log.
- The service loads `sps.env` at start and reads SP_TLS_CERT/KEY/CA from there.

For production, replace the self-signed cert with one signed by your
internal CA; the runner + tools already honor `SP_TLS_CA`.

### Operator provisioning (`sps vault-set / vault-get`)

For the localfile plugin (the dev / single-host default), secrets are set
against the encrypted vault directly:

```bash
SP_VAULT_PASSPHRASE=t python3 -m sps.cli vault-set echo API_KEY <<< hello
python3 -m sps.cli vault-get echo API_KEY
```

Vault-set is for operator provisioning, NOT for the tool's runtime
writeback path; tools call `write_secret` over the wire.

## Plugins

The plugin harness is one class per backend with three methods:

- `connect()` → backend-session-ready object (often `self`)
- `get_secret(field, item) → str`
- `write_secret(field, item, value) → None`

Three ship in-tree; one is loaded at startup (`SP_PLUGIN=`):

- **`infisical`** (HTTP) — auth via machine identity, KV lookup by
  `(environment, secretPath, secretKey)`.
- **`hashicorp_vault`** (KV-v2 over HTTPS) — auth via `X-Vault-Token`;
  configurable mount (`secret` by default).
- **`localfile`** (scrypt + Fernet) — `toolyard.secrets.VaultBackend`
  lifted wholesale; passphrase read from `SP_VAULT_PASSPHRASE` (or
  `_FILE`). Needs the `cryptography` extra.

### Adding a new plugin

1. Subclass `sps.plugins.base.SPSSecretsPlugin`; implement `connect`,
   `get_secret`, `write_secret`.
2. Add a block to `sps.env` for your plugin's config (your plugin reads
   `sps.config.Config.<your_name>`).
3. Add a branch to `sps.plugins.loader.load_plugin`.
4. Add a test class `sps/tests/test_plugin_<your_name>.py` modeled on
   `test_plugin_infisical.py` (a `_StubResponse` class is enough; the
   plugin wire is just urllib + JSON).
5. Update `deploy/sps.env.example` with the new block documented.

## Layout

```
sps/
├── __init__.py
├── audit.py            # append-only JSON-lines; tool_id/action/ts
├── cli.py              # serve | init | vault-set | vault-get
├── client.py           # SPSClient (TLS/TCP, one socket per call)
├── config.py           # sps.env parser + mode-0600 enforcement
├── handlers.py         # 5 ops: register / unregister / get_secrets /
│                       #          get_secret / write_secret
├── plugins/
│   ├── base.py
│   ├── infisical.py
│   ├── hashicorp_vault.py
│   ├── localfile.py
│   └── loader.py
├── server.py           # TCP server + dispatcher + cert wrapping
├── store.py            # in-memory TOOL_REGISTRATION pool (no disk)
├── tool_sdk.py         # SecretClient (tool-side wrapper)
├── wire.py             # JSON-line protocol: read_one_json / write_one_json /
│                       #                  err_envelope / MESSAGE_SET
└── tests/              # 87+ unit + wire-end-to-end tests
```

## Security posture

| Layer | Defense |
|---|---|
| **Config** | Mode 0600 enforced at startup; failure → immediate `Unauthorized` on every register/unregister until fixed. |
| **Transport** | TLS only; server cert verified against `SP_TLS_CA` by every client. Body ≤ 1 MiB; socket read timeout 5 s. |
| **Auth compare** | `hmac.compare_digest` on `spsecret` (runner→SPS) and `esecret` (tool→SPS), body fields. |
| **Audit** | Append-only JSONL; allowed keys `{ts, action, tool_id, secret_name}`. SP/E secrets cannot be passed to `event()`. |
| **Error envelope** | Fixed set: `Bad request / Unauthorized / Not found / Not writable / Backend error`. No payload, no stack trace, no backend body. |
| **Plugins** | Each is its own module, loaded by name at startup; failure to construct the plugin fails-closed (process exit). |
| **In-memory store** | `kill -9` + restart = all registrations lost → runner re-registers on next tool start. This is *deliberate*: a recycled pid would map to the wrong tool. |

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Unauthorized` on every register/unregister | `sps.env` not mode 0600. `chmod 600 /etc/toolstack/sps.env`. |
| `Bad request` from a tool | Tool is sending `>1 MiB` body, or body is invalid JSON, or missing `op` field. |
| `Not found` | Tool id not registered with SPS, or `name` not in the tool's CS_TUPLE list. Verify the runner's register-call log (`TOOL_REGISTRATION` audit event). |
| `Not writable` | `write_secret` against a CS_TUPLE whose `writable` is not true. Fix the tool's `toolyard.toml`. |
| `Backend error` | Plugin's `get_secret`/`write_secret` raised. Check the plugin's own logging — the SPS never exposes backend error bodies. |
| TLS handshake fails (tool side) | `SP_TLS_CA` mismatch, or CA bundle unreadable, or self-signed cert without `IP:127.0.0.1` SAN. |
| Plugin refuses to start | `SP_PLUGIN` set but the matching `[block]` is missing. SPS fails closed with a clear error. |

## Where this fits

SPS is the **SecretsManagementService.workload-half** from the original
9-service decomposition, hoisted into its own process and made pluggable
on the back-end side (the runner is no longer in the read path).
The broker remains the authority boundary; SPS is *its own* authority
boundary for secrets. See [PROJECT.md](../PROJECT.md) and
[plan.md](../plan.md).

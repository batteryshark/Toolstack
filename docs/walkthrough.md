# Toolstack walkthrough: trusted process + SPS

Read [deployment](../deploy/README.md) and [runtime matrix](runtime-matrix.md) first.
This is a fake-config development recipe, not hostile-code isolation or a production
certification. Use Python 3.11+, a dedicated venv, temporary directories and loopback.

1. Install the built wheel with the exported deployment requirements/constraints
   in an isolated venv. Run from a directory outside the checkout to verify imports.
2. Set `umask 077`. Create private config/state/log directories. Set XDG_CONFIG_HOME
   and XDG_STATE_HOME to the temporary directories before invoking any component.
3. Run `deploy/bootstrap-sps.py` with `--config TEMP/config/sps.env`,
   `--state-dir TEMP/state` and `--log-dir TEMP/log`. This makes development TLS
   material with localhost/127.0.0.1 SAN; never disable certificate verification.
4. With SPS stopped, export an explicitly fake `SP_VAULT_PASSPHRASE`, run
   `sps init-vault --config TEMP/config/sps.env`, then pipe a fake value to
   `sps vault-set --config TEMP/config/sps.env demo API_KEY`. Do not use live providers.
5. Start `sps serve --config TEMP/config/sps.env` on loopback. Set
   TOOLSTACK_SPS_BOOT_ID_PATH under TEMP/state to avoid system locations.
   Configure the runner's SPS config/CA using its resolved environment
   contract; registration settings and child settings must agree.
6. Run `admin set-password` interactively and `admin serve --port 8780`.
   The web panel is the reference operator flow: configure broker/tools root,
   start broker, import a trusted process tool, declare its SPS mapping, and start it.
   Create a fake caller, explicitly grant its operation and exercise it over loopback.
7. Stop tools/admin/SPS and remove temporary data after testing. This recipe is not
   itself a test result; see the [reported validation boundary](security-contracts.md#dependency-and-validation-evidence)
   for the exercised restart/recovery flow and its limits.

## Authority and limits

The broker authorizes actions; SPS authorizes a registered tool's read/write mappings.
SP_SECRET is broad runner registration authority. E_SECRET is per-registration
workload capability. Broker uses independently random channel credentials from
dedicated channels.json, never E_SECRET/private state. No filename can isolate the
same unrestricted OS user. Tools can return secrets in results; writeback does not
automatically redact responses. Configure forwarder response redaction explicitly.

Policy is explicit allow/review/deny with missing grants denied in the repaired
broker. Verify the integrated broker version: historical refresh-name exemptions
must not be relied on. Human approval is polled, not pushed execution authority.
SQLite/audit data can contain sensitive operational information and is not a
tamper-proof record. Redaction patterns do not prove arbitrary arguments secret-free.

SPS decrypts localfile data in memory and tools cache plaintext values. Restart loses
registrations; runner recovery must restore current grants and retry failures. Stop
SPS before direct localfile provisioning to avoid stale competing writers. Native
and desktop surfaces have separate contracts and validation; full parity is not claimed.

Schema3 caller-scoped receipts, manual pruning and new-only restore remain integrated
in the current product boundary `78ea904` (unchanged at `8e4bb2e`). For a fake call, choose a stable nonsecret key:
`toolstack call echo.say '{"a":1}' --idempotency-key walkthrough-1 --wait`.
Matching caller/key/payload returns old receipt, NEVER new execution; changed
payload conflicts409. Current allow OR review permits historical reads; deny or
revoked presented token withholds them. Unknown is uncertain effect, not permission
to retry with a new key. CLI incomplete/unknown/expired/conflict exits nonzero.

See [exact retention/offline commands](security-contracts.md#manual-retention-and-offline-recovery)
before maintenance: prune terminal payloads strictly older than seven days; preserve
tombstones; do not copy only the DB while WAL is live. Stop ALL broker/admin/CLI
writers before --confirm-offline reconcile/restore. Restore only to a NEW private
destination; all tokens revoked, all policies cleared, UUID rotated. Original source
is untouched, no effects replayed. Keep authority revoked until external history
(including post-snapshot effects/keys) is reconciled; never blindly replay queues.
These commands do not restore SPS/provider state or guarantee secure erasure.

Use the current lock (`cryptography` 50.0.2; supported range `>=50.0.2,<51`), not
the historical 45.x range. The reported local fake-data checks do not certify a
production deployment or host isolation. The accepted Linux functional witness
includes real process/SPS checks and bounded Docker build/start, but not this
recipe's clean installed deployment; see the [milestones and cleanup limits](runtime-matrix.md).

# Installed-wheel acceptance (parent-only runtime)

The worker implemented and pure-tested this harness without launching its runtime.
Parent review and the sole actual run determine acceptance; unit success is not a
synthetic fullstack acceptance result.

Parent must hash the retained `toolstack-0.1.0-py3-none-any.whl` in
`toolstack-release-artifacts-parent.PLguZR/artifacts/python/`, create a fresh venv,
and install that wheel plus `-r admin/requirements.txt -c admin/requirements-lock.txt`.
The expected SHA256 is below. No rebuild or source installation is appropriate.
The parent already prepared `toolstack-installed-stack-parent.cC4Qlj/venv`.

After review, invoke once, under an independent 300-second outer bound:

```sh
<fresh-venv>/bin/python -I -B /absolute/tests/integration/installed_stack.py \
  --root <canonical-absolute-absent-child-of-owned-0700-parent> \
  --wheel-sha256 177b2ced1cd0500da68fd228284f50b74f2c941571ba0db8d606bc18617207c5 \
  --run single
```

Use canonical `/private/var/...`, not symlinked `/var/...`. Root must not exist.
The hash argument is a parent attestation, not verification of wheel bytes by the
helper. Six package origins must resolve within the fresh installed prefix:
admin, broker, client, sps, toolyard, toolstack_forwarder. All service commands
use the venv interpreter with `-I`, private cwd, constructed environment, and no
PYTHONPATH. No httpx dependency. Harness HTTP disables proxies and redirects.

## Actual sequence

* Owned fake Nod HTTP child binds literal loopback port 0; records bounded cards,
  deduplicates by payload/key, and remains pending until a private control file
  supplies a distinct fixture credential and matching opaque reference.
* Real SPS localfile vault and generated TLS; real ProcessRunner, state lock,
  persisted tool state, independent SPS/channel credentials, installed SecretClient.
* Persisted caller/token hash and review/deny policy; real admin HTTP login,
  configuration TTL save with external tool directories, admin-owned broker start.
* Real broker HTTP review and retry; exact approval options, digest/generation,
  private-field omission, no preapproval effect. Explicit fake approval followed
  by real broker poll executes the SDK tool and proves one effect/one card.
* Broker stop/reap via admin before admin restart. Restart recovers TTL, tool
  directories, policy, live tool, token and completed receipt; denied action and
  matching retry prove no replay.

The fixture is **fake Nod**, not real signature verification, a real Nod release
test, human approval evidence, or a sandbox/security isolation proof. SPS restart
is deliberately omitted; required recovery is admin/broker persisted state.
Linux installer and systemd remain **UNTESTED**. No GUI, VM, host services,
keychain, trusted Nod, deployment installer, or production edits are involved.

## Bounds, evidence and limits

Runtime sequence has a 240-second alarm and a separate 30-second cleanup alarm.
HTTP reads have finite timeouts and 1 MiB bounds. Fixture card/effect counts are
bounded. Cleanup uses exact PID birth plus boot checks, never process patterns;
unknown identity refuses signals. Admin API stops broker first, with an exact-PID
fallback. Runner owns its tool cleanup (including its internal partial-start path).
Popen children are waited/reaped. Final PASS requires completed checks, positively
absent recorded PIDs and closed selected listeners. Any uncertain cleanup fails.
Parent must independently verify cleanup even after failure or outer timeout.

Private 0600 evidence includes checks, origins/hashes, process identities, ports,
phase, outcome, and failure **type** only. Root and private fixtures/config/logs are
retained; those fixture files contain fake credentials and must not be published.
Only `evidence.json` and process metadata are intended as redacted receipts.
Loaded-package hashes describe the harness process, not child import tracing.

Known seams for parent review: selected service ports have the usual bind-close
race; root ancestors are checked rather than opened descriptor-relatively. An
admin start response lost after spawning is reconciled from the private state,
exact parent PID, boot/birth and interpreter/module argv before any cleanup
adoption. A persisted intent precedes the sole start POST; it is never resent.
Missing/unknown state fails closed and retains admin for parent investigation;
it does not infer absence or orphan a possible broker by killing admin. An outer
hard kill can interrupt evidence writing/cleanup. No automatic
second acceptance attempt is authorized. Setup/provenance imports precede the
runtime alarm; the parent's 300-second bound covers the complete invocation.

## Pure battery

Run `test_installed_stack.py` with the existing Sdpb0R Python 3.11 runtime,
`env -i`, private HOME/TMPDIR, `PYTHONDONTWRITEBYTECODE=1`, `-I -B`.
Tests mock HTTP handler streams and process probes; no listeners or Popen.

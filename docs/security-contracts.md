# Integrated operator security contracts

Production source boundary: **78ea904**, byte-identical at **7eac4f9**. These are integrated source contracts, not deployment certification or
final release acceptance.

## Supported host and credentials

Only a dedicated Toolstack VM with trusted tools under the same OS account is
supported; agents stay outside the host and use only the broker. Mac same-account
use is development, **not secret isolation**. Enforced separate accounts/filesystem
isolation is not delivered this release. Linux privileged/native helper is disabled;
Docker+SPS and Seatbelt+SPS are refused/unsupported. Mocked/skipped checks are not
enforcement. The accepted Linux functional witness is bounded as described in the
[runtime matrix](runtime-matrix.md). The bounded retained-wheel clean-install check
passed; installed-service deployment and live provider certification remain unproved.

Admin session and CSRF HMACs use separate `session|` and `csrf-v1|` purpose
contexts; legacy tokens are rejected. Malformed session values, non-ASCII signatures
and non-ASCII CSRF tokens fail closed. This is a defensive contract, not evidence
of an exploitable login bypass or unauthenticated oracle. Runner network-policy
tool IDs use whole-string `fullmatch` validation rather than prefix matching.

Runner independently randomizes the channel credential and SPS E_SECRET. Broker
reads only the channel view `channels.json` (or explicit
`TOOLSTACK_TOOLYARD_CHANNEL_STATE`), never E_SECRET or private runner-state fallback.
Tools authenticate the action channel using `TOOLSTACK_CHANNEL_SECRET`, independently
of `TOOLSTACK_E_SECRET`. This reduces capability overlap; trusted host/same-account
processes still have file and memory access. SP_SECRET retains broad registration
authority. Tools and SPS hold plaintext in memory; revocation cannot erase caches.

Refresh and refresh_one need ordinary explicit grants; missing grants deny. Token
revocation prefixes require 12–64 lowercase hex characters, not SQL wildcards.
Policy changes invalidate pending approvals. Immediate and deferred execution claims
recheck current exact caller/presented token, policy, generation and canonical action
binding transactionally. Deferred claims also check approval, deadline and cancellation.
The executing claim is the cancellation commit point; only its winner dispatches,
using the frozen claimed operation. Manifest drift refuses lookup until reload.
Generation binding is not executable-code immutability or hostile-host protection.

## Approval authoring and disclosure

Optional per-operation `approval_fields` selects from the arguments object:

```toml
[[operations]]
name = "send"
approval_fields = ["/destination", "/body/title"]
```

Use at most 32 unique non-root RFC6901 pointers, each at most 256 characters;
only `~0` and `~1` escapes, canonical nonnegative array indices. `/` selects an
empty key; `''` is invalid root. The sole `validate_fields` validator, also imported
by admin, rejects `*` ANYWHERE, including literal-star keys and `/a/*`.
Admin preserves absence versus `[]`; **both visibly omit
ALL arguments**. No disclosure is added automatically by the editor.

Selected subtrees are deliberate operator disclosure. Sensitive-name masking is
not a universal classifier: selected ordinary strings/keys may disclose secrets.
Do not promise safe arbitrary free-text containers. Summaries label omissions,
masking, missing fields and truncation; strings cap at 256 characters, collections
at 16 entries and nesting at 4 levels; field names longer than 64 characters are
omitted/masked. Each selected entry is limited to 1,000 canonical characters and
the selected-entry list to 3,600, reserving room for the envelope and omission
counts. Oversized values get omission labels where space permits; a large early
field does not automatically suppress later small fields.
REST `body` is an opaque string, not automatically JSON-decoded for pointers.
Approvers do not see a complete request and cannot be said to approve omitted facts
with full information.

Reason/justification is always private, never shown to Nod; audit records only
`reason_provided`. Full-request SHA-256 binds canonical private action (complete
arguments/reason plus private random nonce) and operation generation to the approval.
It is **not** an idempotency payload digest. Terminal clearing is not erasure from
WAL/backups. Schema 3 retains the full-action approval bindings and persistent
installation UUID introduced in schema 2, adding receipt key/private payload digest
and pruning metadata. Older binaries refuse newer schema; legacy pending rows
without bindings fail closed.

Client and Nod refuse same- and external-origin redirects. Nod uses an explicit
no-proxy opener and validates its HTTP(S) base URL, refusing missing hosts,
credentials, whitespace/control characters, query, fragment and backslash forms.
Nod must return resolved
status, exact issued option ID/kind pairs `(approve, approve)` or
`(reject, reject_with_text)`, and matching returned request identifiers. Dedupe keys
use persistent `toolstack:{installation_uuid}:{request_id}` namespace. Poll-only,
broker deadline authoritative. Nod is trusted: no independent compromised-service
signature-verification guarantee. Stale visible cards do not restore local authority.

## Caller-scoped receipts and uncertain execution

HTTP accepts optional `Idempotency-Key` on `POST /v1/actions/<tool>.<op>` and native
`POST /mcp` tools/call: exactly `[A-Za-z0-9_-]{1,128}`, case-sensitive, no whitespace.
Duplicate key headers are 400 framing errors. Keys are identifiers, not secrets;
they remain visible in receipts/tombstones. CLI example:

```sh
toolstack call echo.say '{"a":1}' --idempotency-key order-123 --wait
```

No key creates a new request and CLI warns that resubmission can repeat effects.
Both MCP entrances accept `tools/call.params._meta["toolstack/idempotency-key"]`,
not a workload argument. Stdio translates metadata into the HTTP header; native
MCP accepts metadata or header, rejecting different simultaneous values as invalid
params. For example, params can be:

```json
{"name":"echo__say","arguments":{"a":1},"_meta":{"toolstack/idempotency-key":"order-123"}}
```

Schema 3 atomically reserves a unique `(caller_id, idempotency_key)` receipt.
Same caller/key/payload returns original ID/status/result with `reused: true`, never
new execution, Nod polling or resumption of received work. Different payload is
409 conflict; another caller's key is independent. A private SHA-256 payload digest
covers canonical tool/op/arguments/private reason, **excluding generation and the
approval nonce**. Missing arguments become `{}`; absent/empty/whitespace-only reason
becomes null, otherwise values are exact. Sorted compact ASCII JSON, finite numbers,
distinct boolean/integer and integer/float; no Unicode normalization/coercion. The
digest is never public; the independent approval digest remains nonce-bearing.

Matching excludes current generation intentionally: even after a catalog change,
an old key returns the old receipt, NEVER executes the new operation definition.
Historical receipt reads require a live current caller/exact presented token and a
current **allow OR review** grant for the original tool/op. Review permits reading
one's history, not a second approval or new effect. DENY/removal/revoked presented
token withholds results even if another token is active. Checks occur before
returning prior sensitive results and before/after receipt polling. Transactional
authorization cannot retract already-returned bytes or undo a committed effect
after subsequent revocation.

`received`, `pending_approval`, `executing`, `unknown` and `result_expired` are
distinct. Legacy running displays as executing, not pending approval. Store opening
never relabels active work. Durable executing means a claim committed, not proof of
a currently live process; disk failure may leave it until offline reconciliation.
Only positive initial API/forwarder connection-refused non-dispatch evidence yields
failed/tool_unreachable. Other uncertain runtime/response loss or workload HTTP/
JSON-RPC errors conservatively yield unknown/execution_outcome_unknown. Valid handled
error results retain isError. None permits automatic replay, even for reads.

POST maps received/executing/pending_approval to 202, unknown to 502, conflict to
409, invalid to 400, result_expired to 200. Authorized GET receipts remain 200;
withdrawn authority is 403. CLI/MCP wait only on received/pending/executing, stop on
unknown and retain receipt/key; timeout reports broker_status, not fictitious pending
approval. Incomplete/unknown/expired/conflict outcomes are nonzero CLI outcomes;
MCP marks received/executing/unknown/conflict/result_expired isError true. Client
transport/response loss reports `status: unknown, source: client` with original key
or known receipt and no retry loop. Redirects remain refused, but client labels
their uncertain original dispatch unknown rather than proving no effect.

## Manual retention and offline recovery

Run commands only against explicit intended private paths. The following are
operator procedures, not commands run as part of this documentation work:

```sh
python3 -m broker.brokerctl prune-payloads --db /private/state/broker.db
python3 -m broker.brokerctl backup --db /private/state/broker.db --destination /private/backups/snapshot.db
```

Manual pruning has a fixed seven-day default: terminal updated_at must be **strictly
older**; exact seven-day boundary is retained. It clears arguments/private action/
nonce/reason/results and arbitrary approval notes. Normal terminal argument clearing
already occurs immediately. Completed rows become result_expired; unknown stays
unknown. Receipts label `payloads_pruned: true`. Active received/pending/executing
payloads are never pruned. Repeated pruning is idempotent. Caller/key/private-digest/
request tombstones remain indefinitely: matching old keys return expired/terminal
receipts; changed payload conflicts, never new execution. WAL, freelists and backups
may retain bytes: not secure erasure. Choose backup retention/disposal separately.

**Stop ALL other broker/admin/CLI writers before either offline command:**

```sh
python3 -m broker.brokerctl reconcile-offline --db /private/state/broker.db --confirm-offline
python3 -m broker.brokerctl restore-new --snapshot /private/backups/snapshot.db --destination /private/recovery/new.db --confirm-offline
```

Confirmation is an explicit operator assertion, not PID ownership detection, age
heuristics or enforced isolation. Reconcile marks stale received/executing/legacy
running unknown and clears private execution payloads; it replays NOTHING. Never
called automatically at startup or ordinary Store opening.

Backup uses SQLite's backup API including committed WAL, not a main-file-only copy.
Source must exist. Backup and restore publish only to a **NEW destination**: private
0600 staged file, new final parent 0700, validated private owned parents/ancestors.
Unsafe parents/links/hardlinks and destinations appearing at publication are refused
without chmod/clobber. Complete stage is fsynced then atomically hardlinked to the
new destination; owned stage/sidecars are removed, leaving one-link single-file
DELETE-journal snapshot. Cooperative 30s copy-progress budget is not a hard bound on
filesystem stalls. No running DB replacement or power-loss durability beyond these
operations; directory-entry fsync/interrupted-publication recovery is not independently
rehearsed.

Restore opens a private owned regular non-linked snapshot read-only, copies/migrates
a stage, then cancels pending approvals; pending requests become expired/
restore_cancelled; received/executing/legacy-running become unknown/restore_unknown,
their private payloads cleared. **ALL tokens revoked, ALL policies cleared,
installation UUID rotated**. Caller/key/digest tombstones and completed/expired
receipts remain. Newer schema refuses without destination publication or snapshot
mutation. Original source DB/snapshot is untouched; no automatic switch, outward Nod
cancellation or workload replay. Reissuing a token alone does not restore grants.

Inspect receipts/unknown effects and explicitly review/regrant policy and new tokens
before starting a broker on the NEW DB. A stale backup cannot know keys/effects
AFTER its snapshot: keep authority revoked until the operator reconciles external
history, and NEVER blindly replay old agent queues. These commands cannot guarantee
distributed exactly-once effects or infer missing history.

## SPS transport, persistence and private paths

SPSClient response default: 8 MiB including newline; optional client cap 1 KiB–32 MiB.
Provider aggregate response bodies: 8 MiB across nested authentication, project
resolution, retries and bulk calls. Default absolute socket budget 15 seconds;
finite timeout >0 and <=300 seconds; each idle wait is min(5 seconds, remaining).
Inbound request newline-inclusive 1 MiB cap is unchanged. HTTPS verifies normal
CA/hostname; direct configured origins ignore ambient proxies and refuse credentialed
redirects. Infisical retries bounded GET only; no automatic mutation replay or Vault
CAS-conflict retry. Timeout/failure after send may mean mutation already happened.

Late DNS is refused before authenticated send, but OS resolver, flock, fsync, KDF
and scheduling are not hard-preemptible. Worker count is bounded, not a full real-time
guarantee. Localfile cooperating writers lock/reload; Vault read–merge–CAS preserves
siblings and requires read permission for writeback. Directory fsync failure after
replace means persistence is unknown despite possibly changed bytes. No power-loss
erasure, hostile same-user protection or tamper-proof local audit is promised.

Choose a dedicated private immediate parent (0700); new nested directories are 0700.
Unsafe existing parents/files, symlinks, foreign owners and hardlinks are refused
without chmod repair. Vault/audit/lock are 0600; boot identity is nonsecret 0644 under
its private parent. Do not blindly chmod shared `/etc`, state or log directories:
select a separate owned private path. Existing deployment examples are not proof
that a live host has this layout. Audit is local operational evidence, not secure erasure.
Config and `/etc` group-readable traversal is distinct from private secret-state
parents; it does not relax the private-state requirements above.

## Runner and output visibility

Declared-secret tools without SPS refuse before log/spawn. Only explicit
`TOOLSTACK_SPS_SKIP=1` permits trusted-process development with a loud warning;
no-secret tools work without SPS. Unsupported secret-bearing backends still refuse
even with skip. Process mode egress flags do not establish sandbox egress enforcement.

Egress uses original 30-second total deadline including CONNECT/header/body, 5-second
idle waits, 1 MiB request, 4 MiB response/tunnel and 16 slots. Late DNS/connect sends
no authorization; synchronous DNS can hold a slot until return. Partial-send effects
cannot be rolled back by timeout. Login writeback extracts before response redaction;
both true flags hide body and headers. Explicit false is an author choice that may
expose a value to caller/broker. Never claim secrets cannot reach the broker.

## Dependency and validation evidence

The current vault contract is `cryptography>=50.0.2,<51`; `uv.lock` and the deployment
export pin **50.0.2**. This replaces 45.x and the obsolete `<46` cap after seven
reported advisories; use the minimum fixed line and current lock. The dependency
update changed only this locked version. The reported audit of the new lock covered
17 packages with **0 known vulnerabilities and 0 skips**; that is not proof of the
absence of unknown vulnerabilities. A fake legacy vault encrypted under 45 was
read, updated and reopened under 50 successfully. This is compatibility evidence,
not a real-vault migration procedure.

Reported validation provenance (not rerun for this documentation correction).
Production bytes at `7eac4f9` equal `78ea9049a3370688b721e7ff3bda31a8b3f184c3`;
later changes affect test/release/fixture helpers, docs and handoffs only.

| Milestone | Bounded evidence | Limit |
| --- | --- | --- |
| Full tracked Python, `791159cb275ea50a7bafa3bff7b513b774c536a0` | Dynamically discovered 99 modules; 1,224 run, 1,208 pass, 16 skip, 0 fail in 113.824s; 628 Git-bytechecked files / 684 archive members | Not full `8e4bb2e` or future documentation-source qualification |
| Product package, `78ea904` | Retained wheel; SHA-256 below | Packaging evidence; separate bounded installed-wheel result below |
| Installed retained-wheel full stack, `7eac4f9` / production `78ea904` | PASS: 42 harness checks including lifecycle in 2.912s; fresh installed origins/90 package files bound to wheel; 27 loaded module files independently matched; admin restart/persisted recovery and owned cleanup verified | Bounded clean-install check achieved, not full `7eac4f9` qualification; fake Nod, no GUI, SPS restart or real human/signature proof; milestone reported, acceptance pending |
| Native, `78ea904` | 75 tests pass; actual development signing and separate strict/deep verification | See [Mac evidence](mac-local-signing.md); no live hands acceptance |
| Web, after `aa486b2` | Actual WebKit 48 assertions plus 104 Python web tests; prohibited activation policy, two unshown captures | No synthetic/live equivalence |
| Current fixture delta through `8e4bb2e` | Independent 13 pure checks pass; actual isolated-copy sign and separate strict/deep verify while OFF | Helper repair, not full-suite or hands proof |
| Linux, `78ea904` | Real Docker onebox/echo API/echo MCP build/create/start, all 19 process/SPS checks, admin HTTP 200 | Accepted functional witness only; failed cleanup and installation limits in [matrix](runtime-matrix.md) |

Full tracked archive SHA-256:
`ac5554298c6b35d8b7b43fa2375a20eec11e4c1eedd5c8eff154d43cb3226c9c`.
Retained product wheel SHA-256:
`177b2ced1cd0500da68fd228284f50b74f2c941571ba0db8d606bc18617207c5`.

Historical evidence (not current qualification):

- Independent release checks: 15 OK in 0.683s; focused SPS: 40 OK in 30.710s;
  new-wheel check PASS at c7517a2, with the same packaged production code and
  dependencies as c9da2fc.
- At c9da2fc, 55 checks PASS on Python 3.11.17 / cryptography 50.0.2 using actual
  published Nod 1.0.1, verified TLS, fake localfile data, CLI, admin HTTP/HTML/JSON,
  config `tool_dirs`, admin restart, idempotency and recovery. All eight owned
  processes independently exited and temporary data was cleaned.
- The SPS owner's full suite reported 138 OK in 33.783s under 50. This was not an
  independent full-suite rerun. Older 31/55-check results at 105e6ab/45ec3fe are
  historical, not the current proof boundary.

Those older checks are local fake-data Mac development evidence, including the
real signed Nod 1.0.1 integration, not a new Nod/runtime claim. Linux systemd
templates have not been installed/run; bounded Docker build/start is now proven.
Docker/Seatbelt with SPS remain unsupported, the Linux mutable helper disabled,
and one-box compose experimental without SPS supervision. Actual Mac development
signing and VM functional evidence do not establish live UI, real-provider,
installed service or production certification.
Temporary-WAL/new-destination restore checks do not prove crash/power-loss recovery.
No final release acceptance is inferred.

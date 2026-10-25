# Approval surface adapter

Current source: 855da6e (broker a9319b9 / release 059dd13). [Security contracts](security-contracts.md) define
disclosure, binding, transport and pending-release limits.

The shipped surface is Nod. Adapter operations are `open(card)`, `poll(ref)` and
best-effort `cancel(ref)`. No inbound callback/push authority exists. Broker owns
policy/deadline/claim; Nod is trusted, not independently verified against compromise.

`open` posts `/api/v1/requests`; `poll` reads
`/api/v1/requests/{request_id}/decision`. Dedupe uses persistent
`toolstack:{installation_uuid}:{request_id}`, not a database integer alone.

Cards show trusted operation metadata/destination, bounded allowlisted summary with
visible omissions, Full request SHA-256 and Operation generation. Reason stays
private. Absent/empty approval_fields visibly omit ALL arguments. Selected fields
are deliberate disclosure, not universally secret-free input. Push redaction is
requested, not a content classifier. See security contracts for pointer authoring.
The shared validator rejects literal `*` anywhere, including literal-star keys;
`/` remains valid and empty root pointer invalid. Admin preserves absent versus [].

Only resolved decisions with issued ID/kind pairs `(approve, approve)` and
`(reject, reject_with_text)` normalize to approval/rejection. Returned request IDs
must match, including optional nested IDs. Prefix matches/unissued options cannot
authorize. Approver/note are metadata. Deferred claim rechecks local authority,
expiry, policy, generation and immutable full-action digest. Same/external-origin
redirects are refused. Nod reads default to 15 seconds and a 1 MiB body cap;
finite constructor timeout is at most 60 seconds. OS DNS is not hard-preemptible.

Card withdrawal is best effort: stale cards do not restore local authority. No
optional independent signature mode or additional surface is claimed this release.

Schema3 caller-scoped idempotency uses a separate private payload digest excluding
generation/approval nonce. Matching retries return the old receipt, never open/poll
Nod or execute a changed operation. Historical reads under a live current allow OR
review grant are receipt access, not a second approval/new effect. Deny/removal or
revoked exact presented token withholds output; already-returned bytes cannot be
retracted. The executing claim remains the cancellation commit point for both
immediate and deferred execution.

Offline restore cancels pending approvals/requests, makes in-flight phases unknown,
revokes ALL tokens, clears ALL policies and rotates installation UUID before
publishing to a NEW destination. No outward card withdrawal or workload replay is
performed. Stale cards cannot execute restored cancelled work. Snapshot history may
miss later effects/keys: reconcile external history before restoring authority,
never blindly replay old queues. See the exact offline procedure in security contracts.

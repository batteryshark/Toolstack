# Approval Surface Adapter Contract

This is the contract a **human-in-the-loop approval surface** must satisfy to
plug into the broker. The reference implementation targets
[nod](https://github.com/batteryshark/nod); this doc exists so you can write your
own (Slack, a webhook, a pager, a custom app) without changing the broker.

If you only ever use nod, you can skip this — the broker ships a nod adapter. Read
on only if you want to swap the surface.

---

## What an approval surface is (and is not)

An approval surface is a **messenger**. When the broker's policy says an operation
needs human review, the broker:

1. builds a redacted **OperationCard**,
2. hands it to the surface (`open`),
3. waits for a normalized **SurfaceDecision** (via `poll` — the authoritative,
   poll-only read), and
4. executes or refuses based on the broker's own rules.

The surface decides *nothing*. It collects a human's answer and reports it back.

**The broker owns approval truth.** A decision from the surface is a *claim*. The
broker validates it, reconciles it against the surface's durable read, and
enforces its own timeout. This is non-negotiable, and it is what keeps a
compromised or buggy surface from being able to authorize an action.

---

## The interface

Implement three operations. Resolution is **poll-only** — there is no inbound
callback (see `deliver` below for why).

### `open(card: OperationCard) -> SurfaceRef`

Publish a prompt for a human. Return an **opaque handle** the broker stores. Must
be **idempotent** on `card.idempotency_key` — the broker may retry `open` after a
network blip, and that must not create a second prompt. The broker enforces the
approval timeout itself, so the surface is not handed an expiry.

### `poll(ref: SurfaceRef) -> SurfaceState`

Return the current state. **This is the durable source of truth the broker trusts.**

```
SurfaceState = {
  outcome:     "pending" | "approved" | "rejected" | "expired" | "cancelled",
  approver_ref: string | null,   # who answered (surface-native id)
  note:         string | null,   # optional human comment
  decided_at:   timestamp | null
}
```

`poll` must be safe to call repeatedly and must keep returning the resolved state
after resolution (not 404).

### `cancel(ref: SurfaceRef) -> void`

Withdraw a still-pending prompt. The broker calls this when its own timeout fires
or the caller's token is revoked. Cancelling an already-resolved request is a
no-op, not an error.

### `deliver(decision)` — rejected (poll-only)

A push/callback fast-path is **deliberately not implemented and not planned.**
There is no broker callback route. The reason is security, not effort: nod posts
its callbacks **unauthenticated** (a plain `POST callback_url` with the decision
JSON — no signature, no shared secret). A broker endpoint that trusted such a
callback would let anyone who can reach it forge an "approved" decision for a
pending request and bypass the human approval gate. So resolution is poll-only,
and `poll` is the sole source of approval truth.

---

## Data contracts

### OperationCard (broker → surface)

Redacted and safe to leave the core trust zone. Describes the **operation**, not
the wrapper (principle #7, *approval describes the operation, not the command*,
from the previous build's principles).

| Field | Required | Meaning |
|---|---|---|
| `idempotency_key` | yes | Stable id for retry-safe `open` (the broker uses its `request_id`). |
| `title` | yes | The decision in one sentence: "Approve `media.skip` for caller `hermes`". |
| `caller` | yes | Which agent/client is asking. |
| `tool`, `operation` | yes | What would run. |
| `target` | no | What it acts on (mailbox, repo, host…). |
| `data_class` | no | Sensitivity of data touched. |
| `risk` | yes | Risk treatment from the policy decision. |
| `policy_reason` | yes | Why policy routed this to review. |
| `blast_radius` | no | One line on what would change. |
| `links` | no | Audit record, runbook, dashboard. |
| `allowed_actions` | yes | Which outcomes the human may choose (approve / reject / …). |
| `expires_at` | yes | When the prompt goes stale. |

**Forbidden in an OperationCard:** raw arguments, secrets, tokens, credentials.
Redaction happens in the broker *before* `open` is called.

**Implementation status:** the current `OperationCard` (broker `approval.py`) and the
nod adapter populate `request_id` (the idempotency key), `title`, `caller`, `tool`,
`op`, `risk`, the policy `reason`, and the agent's `justification`. The richer fields
above (`target`, `data_class`, `blast_radius`, `links`, `allowed_actions`,
`expires_at`) are part of the contract's *intent* but are **not yet populated** —
treat them as optional/forward-looking. The broker owns the approval timeout, so
`expires_at` is not sent to the surface.

### SurfaceDecision (surface → broker)

The normalized result the broker consumes (returned by `poll`):

| Field | Meaning |
|---|---|
| `outcome` | `approved` / `rejected` / `expired` / `cancelled`. |
| `approver_ref` | Surface-native identity of who answered. **Metadata, not authority.** |
| `note` | Optional human comment. |
| `decided_at` | When the human answered. |

Map your surface's native verbs onto `outcome`. Anything that isn't a clear
approve is **not** an approval.

---

## Lifecycle

```
policy: review-required
        │
        ▼
broker builds OperationCard ──open──▶ surface shows a human
        │                                   │
        ├──────────── poll ────────────────▶│  (durable truth, poll-only)
        │◀──────── SurfaceState ────────────┤
        ▼
  approved?  ── yes ──▶ broker executes (forwards to toolyard)
     │
     no / expired / broker-timeout ──▶ fail closed, audit, cancel()
```

---

## Trust & auth requirements

An adapter is only safe if all of these hold:

1. **Outbound credential stays on the broker host.** The surface's issuer/API
   token lives with the broker, never on the agent.
2. **No inbound callback route exists.** Resolution is poll-only, so there is no
   forged-callback surface to defend. A push fast-path is deliberately not built:
   nod's callbacks are unauthenticated, so a receiver would let anyone forge an
   approval.
3. **`poll` is the sole source of truth.** Approval state comes only from `poll`;
   the broker never acts on a pushed decision.
4. **The broker's timer wins.** The broker fails closed on its own timeout and
   ignores any decision that arrives after expiry, even a valid one.
5. **`approver_ref` is metadata.** Identity from the surface is recorded for
   audit, never treated as authority by itself.
6. **Optional hardening:** if your surface signs decisions (nod does, on-device
   P-256), the broker may require a verified signature before honoring an approval.

---

## Reference implementation: nod

| Contract operation | nod call |
|---|---|
| `open(card)` | `POST /api/v1/requests` (strict; returns `request_id`, `deduped`) |
| `poll(ref)` | `GET /api/v1/requests/{request_id}/decision` |
| `cancel(ref)` | nod issuer cancel |
| `deliver(decision)` | *not implemented* — no broker callback route (poll-only by design) |

**OperationCard → nod `CreateDecisionRequest`:**

| OperationCard | nod field |
|---|---|
| `title` | `title` |
| `caller` / `tool` / `operation` / `target` / `data_class` / `risk` / `policy_reason` | `fields[]` (`{label, value, style}`) |
| `blast_radius` | `body_markdown` |
| `links` | `links[]` (`{label, url}`) |
| `allowed_actions` | `options[]` — `approve`, `approve_with_text`, `reject_with_text` (mark destructive) |
| *(timeout)* | broker-internal — the broker enforces the deadline; `expires_at` is not currently sent to nod |
| `idempotency_key` | `dedupe_key` |
| (push safety) | `notification.redact: true` |

**nod decision → SurfaceDecision:** `option_kind` `approve*` → `approved`,
`reject*` → `rejected`, `dismiss` → treated as no-approval; `text` → `note`;
`actor_user_id` → `approver_ref`. The adapter parses this from the decision-read
response only. (nod can also POST the same `decision` object to a `callback_url`,
but the broker has no callback route, so that payload is unused.)

nod request model authored in detail by nod's own skill:
[agent-skills/nod-notification-author](https://github.com/batteryshark/nod/tree/main/agent-skills/nod-notification-author).

---

## Adapter correctness checklist

- [ ] `open` is idempotent on `idempotency_key`.
- [ ] `poll` returns durable state and keeps returning it after resolution.
- [ ] `cancel` is a no-op on already-resolved requests.
- [ ] No raw arguments or secrets ever appear in an OperationCard.
- [x] No inbound callback route exists (poll-only); there is no forged-callback surface.
- [ ] The broker reads every approval via `poll` before executing.
- [ ] Decisions after broker timeout are ignored.
- [ ] Native verbs map cleanly to `outcome`; ambiguous = not approved.

---

## Minimal adapter skeleton

```python
class ApprovalSurface:
    def open(self, card: OperationCard) -> SurfaceRef: ...
    def poll(self, ref: SurfaceRef) -> SurfaceState: ...
    def cancel(self, ref: SurfaceRef) -> None: ...
    # No deliver()/callback route: resolution is poll-only by design
    # (nod's callbacks are unauthenticated, so a receiver would be forgeable).
```

Implement those three methods against your surface, satisfy the checklist, and the
broker can use it in place of nod.

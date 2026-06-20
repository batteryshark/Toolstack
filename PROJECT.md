# Project Nerve Center

The restart point for the Toolstack rebuild.

## Mission

Build a brokered, action-without-access tool layer for agents — slowly, one
component at a time, with ultra-simple code and physical trust boundaries a junior
engineer can understand at a glance.

The system should be understandable to a new reader without knowing the old
implementation or any previous design attempt.

## Architecture direction

**Collapse to deployment reality** (decided 2026-06-13). A few processes with hard
boundaries, not a mesh of logical services. The fine-grained ownership rules from
the earlier decomposition survive as **module seams inside the broker**.

## Current shape

- Review walkthrough (start here to re-orient): [docs/walkthrough.md](docs/walkthrough.md).
- Buildable plan, components, and build order: [plan.md](plan.md).
- Diagrams, broker internals, and trust boundaries: [docs/component-decomposition.md](docs/component-decomposition.md).
- Boundary wire contracts and invariants: [docs/message-contracts.md](docs/message-contracts.md).
- Approval-surface adapter contract ("SDK"): [docs/approval-surface-adapter.md](docs/approval-surface-adapter.md).
- How an agent connects and calls tools: [client/SKILL.md](client/SKILL.md).
- Operator control panel (run the broker, manage clients/tools, watch audit): [admin/README.md](admin/README.md).
- Clean-code expectations: [docs/coding-standards.md](docs/coding-standards.md).

## Working rules

- Build one component at a time; each phase ends in something you can run.
- Boring, explicit code over clever abstraction; keep public surfaces small.
- Fail closed everywhere.
- Secrets live with the workload. The broker holds no secret-backend credential and
  is never on the secret path.
- The registry is secret-unaware: the broker reads tool/op/risk/port from
  `toolyard.toml` and ignores the `[[secrets]]` block.
- The broker owns approval truth; nod is a messenger (poll-only — there is no
  callback route; the broker's timeout wins).
- The broker forwards approved calls directly to the tool container; toolyard is not
  in the request path.
- Defer until a component needs it: profiles, mTLS / component credentials between
  hosts, multiple approval surfaces, sandboxed jobs.

## Current status

**The planned build order (Phases 0–4) is complete and tested**, and an operator
**admin web app** now runs the whole stack. The full vertical slice runs end to end:
agent → broker (auth + policy) → human approval in nod → tool execution with workload
secrets, and the broker never sees a secret.

Phase 4 (admin + hardening) added `brokerctl` to manage callers/policies/tokens
(admin actions audited), per-caller rate limiting, immediate revocation, `reason`
redaction, and an audit trail that answers the four questions. The agent-side client
(the `toolstack` CLI + MCP adapter + skill) is built on top.

The [admin web app](admin/README.md) (FastAPI — the one component with runtime deps)
supervises the broker process, manages callers/tokens/policies, **authors and edits
tools** (writes their `toolyard.toml` from a form into a directory you name, which the
broker then discovers), and shows requests + audit. It shares the broker's `Store` and
`broker.operations`, so the panel and `brokerctl` write **one** audit trail; it binds
loopback only and keeps secrets off the browser. 509 tests pass across [broker/](broker/)
(219), [toolyard/](toolyard/) (78), [client/](client/) (23), [admin/](admin/) (180), and
[desktop/](desktop/) (9), plus opt-in docker + live-nod/Infisical + vault (`[vault]` extra)
tests and a full author → register → run → call live walkthrough. The admin also serves a
JSON operator API (`/api/*`) for native clients, consumed by a native SwiftUI macOS app
([macapp/](macapp/) — `ApiClient` + core screens; 31 `swift test` tests).

## Suggested next step

Harden for real deployment:

- The deferred items — container **tmpfs** secret injection (no host disk),
  temporary grants/JIT elevation, and a background approval-expiry sweeper.
- Wire a real nod + secret backend (Infisical/SOPS) + tailnet per
  [broker/README.md](broker/README.md) and [toolyard/README.md](toolyard/README.md).
- Component-credentials/mTLS only if modules ever split across hosts.

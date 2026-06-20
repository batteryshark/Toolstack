<p align="center">
  <img src="macapp/packaging/AppIcon-source.png" alt="Toolstack logo" width="150" height="150">
</p>

# Toolstack Rebuild

A brokered, action-without-access tool layer for agents: the agent can *ask*, the
broker *decides*, tools *execute*, and secrets stay with the tools.

(**Toolstack** is the product — the package, the `toolstack` / `brokerctl` / `toolyard` CLIs,
and the `TOOLSTACK_*` env vars. Some docs still carry the old **TSR** / "Toolstack Rebuild"
working name from the from-scratch rebuild.)

Start with **[docs/walkthrough.md](docs/walkthrough.md)** — the review walkthrough
(what it is, how it runs, the security properties). [plan.md](plan.md) is the
component-by-component build plan, [PROJECT.md](PROJECT.md) is the nerve center, and
[docs/component-decomposition.md](docs/component-decomposition.md) has the diagrams and
trust boundaries.

## What you build

- **Broker** — the authority boundary and the only address the agent has: auth,
  policy, request lifecycle, approval orchestration, and audit. One process, one
  SQLite file. (Internally split into module seams — see the architecture doc.)
- **Toolyard** — container lifecycle + per-tool secret resolution at container start.
- **Tool template** — what a new tool needs (drop a `toolyard.toml`, run `toolyard up`).
- **Approval adapter** — a broker module that talks to nod; pluggable via
  [docs/approval-surface-adapter.md](docs/approval-surface-adapter.md).
- **Agent client** — the generic `toolstack` CLI + skill (and an MCP adapter) an
  agent uses to discover and call tools through the broker; see
  [client/SKILL.md](client/SKILL.md).
- **Admin web app** — the operator's control panel: run the broker, manage
  callers/tokens/policies, author/edit tools (form → `toolyard.toml`), and watch
  requests + audit. Local/homelab, loopback-only; see [admin/README.md](admin/README.md).
- **Operator apps** — a cross-platform desktop shell ([desktop/](desktop/), an OS-WebKit window
  around the admin) and a native macOS app ([macapp/](macapp/), SwiftUI over the JSON API).

## What you deploy

- **nod** — self-hosted approval surface for human-in-the-loop decisions.
- **Secret backend** — Infisical or SOPS.
- **Tailnet** — Tailscale Serve (or any VPN); the ingress boundary.

## Install

The broker, toolyard, and client are stdlib-only Python (3.11+, for `tomllib`). Install the
repo to put the CLIs on your PATH:

```bash
pip install -e .          # editable — the commands track your checkout
toolstack --help
```

This installs `toolstack` (the agent client), `brokerctl` (operator CLI), `toolyard` (tool
runner), and `toolstack-mcp` (the client as an MCP stdio server). Runtime stays
zero-dependency; each also runs uninstalled as `python3 -m client.toolstack`,
`python3 -m broker.brokerctl`, etc. The **admin web app** carries the only runtime deps
(FastAPI/uvicorn) and has its own venv — see [admin/README.md](admin/README.md).

For a real (systemd) install — the admin panel supervising the broker, with an
`EnvironmentFile`, the supervision model, and verification steps — see
[deploy/README.md](deploy/README.md).

## Status

The planned build order (Phases 0–4) is **complete and tested**, with an operator
**admin web app**, a desktop shell, and a native macOS app on top — 513 tests across
[broker/](broker/), [toolyard/](toolyard/), [client/](client/), [admin/](admin/), and
[desktop/](desktop/), plus 32 `swift test` tests for the native app ([macapp/](macapp/)).
The full vertical slice runs end to end:
agent → broker (auth, policy, request lifecycle) → human approval in nod → tool
execution with workload secrets, and the broker never sees a secret. Operators manage
callers/policies/tokens with `brokerctl` or the [admin panel](admin/README.md). It is
**hardened for a real (single-host) install** — systemd state-dir + sandbox, admin login
throttle + bind/SSRF guards, runtime timeouts + partial-failure cleanup, pinned deps, and
DB backups (see [deploy/README.md](deploy/README.md)). A few **narrower items stay deferred**
— container tmpfs secret injection, JIT/temporary grants, a background approval-expiry sweeper
(see [docs/walkthrough.md](docs/walkthrough.md)). See [plan.md](plan.md) for the build order and
[PROJECT.md](PROJECT.md) for what's next.

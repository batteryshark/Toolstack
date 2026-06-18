# Toolstack Rebuild

A brokered, action-without-access tool layer for agents: the agent can *ask*, the
broker *decides*, tools *execute*, and secrets stay with the tools.

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
**admin web app** on top — 296 tests across [broker/](broker/), [toolyard/](toolyard/),
[client/](client/), and [admin/](admin/). The full vertical slice runs end to end:
agent → broker (auth, policy, request lifecycle) → human approval in nod → tool
execution with workload secrets, and the broker never sees a secret. Operators manage
callers/policies/tokens with `brokerctl` or the [admin panel](admin/README.md). It is
**not yet deployment-hardened** — see the deferred items in [docs/walkthrough.md](docs/walkthrough.md)
before running it for real. See [plan.md](plan.md) for the build order and
[PROJECT.md](PROJECT.md) for what's next.

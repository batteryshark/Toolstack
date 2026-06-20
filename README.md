<p align="center">
  <img src="macapp/packaging/AppIcon-source.png" alt="Toolstack logo" width="150" height="150">
</p>

# Toolstack

**Trust agents with action, not access.** An agent can *ask*; the broker *decides*; tools
*execute*; secrets stay with the tools. The agent can reach the broker — and nothing else.

The security comes from physical boundaries — a single ingress, loopback binding, and
secrets resolved at the workload — not from rules on paper. The agent carries only a
low-power token to the broker; everything sensitive lives behind it.

## Components

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

## You also run

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

## Maturity

The full path runs end to end — agent → broker → human approval → tool execution, with the
broker never holding a secret — and it's hardened for a single-host deployment: a systemd
state directory and sandbox, login throttling, bind and SSRF guards, runtime timeouts with
partial-failure cleanup, pinned dependencies, and database backups. It binds loopback by
default; reach it over a tunnel that terminates TLS. A few things are deliberately deferred:
tmpfs secret injection, just-in-time grants, and a background approval-expiry sweeper.

## Docs

- [docs/walkthrough.md](docs/walkthrough.md) — the system end to end: how it runs, the security properties, and the evidence.
- [docs/component-decomposition.md](docs/component-decomposition.md) — architecture, broker internals, and trust boundaries.
- [admin/README.md](admin/README.md) · [broker/README.md](broker/README.md) · [toolyard/README.md](toolyard/README.md) — per-component detail.

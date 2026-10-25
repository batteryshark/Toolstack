<p align="center">
  <img src="macapp/packaging/AppIcon-source.png" alt="Toolstack logo" width="150" height="150">
</p>

# Toolstack

**Trust agents with action, not access.** An agent can *ask*; the broker *decides*; tools
*execute*; secrets stay with the tools. The agent can reach the broker, and nothing else.

## What it is

Toolstack is a small, self-hosted tool layer for AI agents. Instead of handing an agent API
keys and letting it call services directly, you give it one low-power token for one address:
the broker. The broker checks who is asking, whether that action is allowed, and (if you said
so) asks a human first. Only then does it forward the call to the tool, and the tool fetches
its own credentials from a local secrets service (SPS). The agent never sees a secret.

## What it's for

Personal and homelab infrastructure: one person (or a small trusted group) running their own
agents against their own accounts and services, such as email, calendars, home automation,
internal APIs and scripts. You decide which agent may do what; anything risky can wait for
your thumbs-up on your phone.

## Why it exists

Agents are useful when they can act, and dangerous when they hold the keys. Most setups put
tokens in the agent's environment and hope the prompt keeps it in line. Toolstack takes the
opposite approach: the security comes from physical boundaries (one ingress, loopback
binding, secrets resolved at the workload), not from rules the agent is asked to follow. The
code is deliberately boring and small enough to read in an afternoon.

## What it is not

- **Not a customer-facing or multi-tenant platform.** There are no tenants, quotas, billing,
  SSO, high availability or horizontal scaling, and none are planned.
- **Not a sandbox for hostile code.** Tools are code you trust. Toolstack controls what an
  agent may *ask for*, not what a malicious tool could do on its host.
- **Not a secrets manager.** SPS hands each running tool only the secrets it was granted; your
  vault (local file, Infisical or HashiCorp Vault) stays the source of truth.

## How it fits together

```
agent ──token──▶ broker ──▶ tool ──▶ SPS ──▶ your vault
                   │
                   └──▶ nod (optional human approval on your phone)
```

- **Broker**: the only address an agent has. Authentication, per-caller policy
  (allow / review / deny per tool action), approvals, receipts and audit. One process, one
  SQLite file.
- **Toolyard**: starts and stops tools (each described by a `toolyard.toml`). REST APIs can be
  wrapped without code through the [REST forwarder](docs/rest-forwarder.md).
- **SPS** (Secrets Procurement Service): gives each started tool exactly the secrets it was
  granted, over local TLS. See [docs/sps.md](docs/sps.md).
- **Admin**: the operator's control panel for callers, policies and tools, as a web page, a
  desktop window ([desktop/](desktop/)) or a native Mac app ([macapp/](macapp/)).
- **Agent client**: the `toolstack` CLI, a skill and an MCP adapter an agent uses to discover
  and call tools ([client/SKILL.md](client/SKILL.md)).
- **nod** (separate project): the approval app that asks you to approve or reject.

## Where to run it

On **one dedicated machine or VM that runs only Toolstack and the tools you trust**, with your
agents somewhere else, reaching only the broker (for example over Tailscale). Everything on
the Toolstack host shares one OS account, so that host is the trust boundary. Running agents
on the same machine (say, your Mac) is fine for development, but it does not keep secrets
from them.

## Run it

On a fresh Linux VM (Ubuntu tested), as root, from a checkout in `/opt/toolstack`:

```bash
git clone https://github.com/batteryshark/Toolstack /opt/toolstack
sudo /opt/toolstack/deploy/install.sh
```

The installer creates the `toolstack` service account, the virtualenv, the admin password
and the systemd units. Then bootstrap SPS once, as described in
[deploy/README.md](deploy/README.md), and open the panel through an SSH tunnel to
`127.0.0.1:8780`. Everything listens on loopback only.

To try it locally with fake data first, see the [walkthrough](docs/walkthrough.md).

Python 3.11+ is required. `pip install .` puts the CLIs on your path: `toolstack` (agent
client), `brokerctl` (operator), `toolyard` (tool runner) and `toolstack-mcp` (MCP adapter).
Installing the CLIs starts nothing; they talk to a broker you run.

## Status

Used for personal infrastructure, hardened for a single-host deployment: fail-closed defaults,
login throttling, trusted-host checks, server-side sign-out, bind and redirect guards,
bounded requests, private state files, pinned dependencies and database backups. Known limits
are listed in the [security contracts](docs/security-contracts.md) and
[release notes](docs/release-notes.md). Docker one-box and sandbox runners are experimental
and not supported together with SPS.

## Docs

- [Walkthrough](docs/walkthrough.md): the system end to end, with fake data.
- [Architecture and trust boundaries](docs/component-decomposition.md)
- [Security contracts](docs/security-contracts.md) · [Runtime matrix](docs/runtime-matrix.md)
- [Deployment and SPS provisioning](deploy/README.md) · [SPS](docs/sps.md)
- [Tool secret declarations](docs/secret-declarations.md) · [REST forwarder](docs/rest-forwarder.md)
- Per component: [admin](admin/README.md) · [broker](broker/README.md) · [toolyard](toolyard/README.md)
- [Design notes](PROJECT.md) · [Release notes](docs/release-notes.md)

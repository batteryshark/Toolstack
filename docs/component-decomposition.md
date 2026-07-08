# Architecture

How the system works, and why. Read [PROJECT.md](../PROJECT.md) for the summary
and [plan.md](../plan.md) for the buildable, component-by-component plan.

**Direction:** the system is *collapsed to deployment reality*, a few processes
with hard physical boundaries, not a mesh of logical services. The detailed
ownership rules live as **module seams inside the broker** (second diagram).

## Physical picture (the boundary is the architecture)

```mermaid
flowchart TB
    subgraph Untrusted["Agent host, untrusted"]
        Agent["Agent / client<br/>holds only a low-power broker token"]
    end

    Ingress["Tailnet / VPN ingress<br/>(the ONLY path in)"]

    subgraph BrokerHost["Broker host, authority boundary (one process)"]
        Broker["Broker<br/>auth · policy · request lifecycle<br/>approval orchestration · audit<br/>reads tool registry from disk"]
        DB[("SQLite<br/>callers · tokens · requests<br/>approvals · audit")]
    end

    subgraph Workload["Tool runtime, execution boundary"]
        Toolyard["Toolyard<br/>container lifecycle + secret resolution<br/>(not in the request path)"]
        Tools["Tool containers<br/>127.0.0.1:port · secrets at /run/secrets (target: tmpfs)"]
    end

    Nod["nod<br/>approval surface (external)"]
    Vault["Secret backend<br/>Infisical / SOPS (external)"]

    Agent --> Ingress --> Broker
    Broker --> DB
    Broker -->|forward approved call| Tools
    Toolyard -->|start + inject secrets at container start| Tools
    Broker <-->|open approval / read decision| Nod
    Toolyard -->|resolve secrets| Vault
    Broker -. never on the secret path .-> Vault
```

Typically the broker, toolyard, and tool containers all run on **one host**,
isolated by process and container boundaries and bound to `127.0.0.1`. The tailnet
is the only way in; nod and the secret backend are the only things reached out to.

Note the request path: the broker forwards an approved call **directly to the tool
container** on its localhost port (it learns the port from the registry it reads
off disk). Toolyard's job is to *start* containers and *inject* their secrets at
boot; it is not a proxy between the broker and the tools.

## Inside the broker (module seams)

```mermaid
flowchart TB
    subgraph Broker["Broker process, one SQLite file, in-process calls only"]
        Gateway["Gateway<br/>ingress · egress · correlation id"]
        Identity["Identity<br/>callers · hashed tokens"]
        Lifecycle["Request lifecycle<br/>state · orchestration"]
        Policy["Policy<br/>allow · review · deny"]
        Registry["Registry-read<br/>tool/op/risk/port from toolyard.toml<br/>(ignores the [[secrets]] block)"]
        Approval["Approval<br/>orchestration + nod adapter"]
        Audit["Audit<br/>append-only, every module writes here"]
        Gateway --> Identity
        Gateway --> Lifecycle
        Lifecycle --> Policy
        Lifecycle --> Registry
        Lifecycle --> Approval
    end
    Lifecycle -->|forward approved call| Tool["Tool container 127.0.0.1:port"]
    Approval <-->|open / read decision| NodSurface["nod"]
```

These are modules in one process, not services. Each keeps the ownership rule it
had when it was a "service" (see the module table in [plan.md](../plan.md)). They
share one SQLite file and call each other in-process: **no network and no
inter-module auth**, which is exactly the cost the collapse removes. Every module
records to the Audit module.

## Trust boundaries

| From → To | Path | Auth |
|---|---|---|
| Agent → Broker | Tailscale Serve (tailnet-only) | Bearer token bound to one caller |
| Broker → Tool container | localhost HTTP / JSON-RPC | Optional per-tool shared secret (defense in depth) |
| Toolyard → Secret backend | HTTP | Toolstack-wide machine identity kept on the host |
| Tool container → Secret backend | none | Reads `/run/secrets/<name>`; writable fields via toolyard's Unix socket |
| Broker → nod | HTTP over tailnet | nod issuer token (on the broker host) |
| nod → Broker (callback), *not implemented, not planned* | - | No callback route exists; resolution is poll-only. Rejected on security grounds: nod posts callbacks unauthenticated, so a receiver would let anyone forge an approval. |
| Operator → Broker | CLI on the host | Direct SQLite / `brokerctl` |

## What holds the line

The controls live in the [security-spine invariants in plan.md](../plan.md): fail
closed; secrets never on the control plane; registry secret-unaware (physically);
redact before any boundary; tokens hashed and revocation immediate; approval
describes the operation; the broker owns approval truth; every decision audited.

## Why it's shaped this way

The agent can reach only the broker, over one tunnel. The broker decides. The tool
executes with its own secrets, which the broker never sees. Risky operations go to
nod for a human. One host, localhost binding, and a tailnet keep the whole thing
deployable on a laptop and auditable end to end, while the broker's internal
module seams keep the roles from collapsing into one tangled blob.

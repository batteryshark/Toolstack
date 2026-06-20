# Design notes

Why Toolstack is shaped the way it is: the mission, the architecture decision behind it, and
the principles every component holds to. For how it runs end to end see
[docs/walkthrough.md](docs/walkthrough.md); for the diagrams,
[docs/component-decomposition.md](docs/component-decomposition.md).

## Mission

A brokered, action-without-access tool layer for agents: ultra-simple code with physical
trust boundaries a junior engineer can understand at a glance. It should make sense to a new
reader with no knowledge of any previous design.

## Architecture

A few processes with hard boundaries, not a mesh of logical services. The fine-grained
ownership rules from the original decomposition survive as **module seams inside the broker**:
one process, one SQLite file, internal seams rather than a service mesh.

## Principles

- Boring, explicit code over clever abstraction; keep public surfaces small.
- Fail closed everywhere.
- Secrets live with the workload. The broker holds no secret-backend credential and is never
  on the secret path.
- The registry is secret-unaware: the broker reads tool / op / risk / port from `toolyard.toml`
  and ignores the `[[secrets]]` block.
- The broker owns approval truth; nod is a messenger: poll-only, with no callback route, and
  the broker's timeout wins.
- The broker forwards approved calls directly to the tool container; the toolyard is not in the
  request path.
- Defer until something needs it: profiles, mTLS / component credentials between hosts,
  multiple approval surfaces, sandboxed jobs.

## Deferred

Deliberately not built yet: tmpfs secret injection (so secrets never touch host disk),
just-in-time / temporary grants, and a background approval-expiry sweeper; expiry is lazy
today (on the next poll, the next submit, or `brokerctl sweep`). Component credentials / mTLS
matter only if the modules ever split across hosts.

## Documentation

- [docs/walkthrough.md](docs/walkthrough.md): the system end to end.
- [docs/component-decomposition.md](docs/component-decomposition.md): diagrams, broker internals, trust boundaries.
- [plan.md](plan.md): component-by-component design and the cross-cutting invariants.
- [docs/message-contracts.md](docs/message-contracts.md): boundary wire contracts.
- [docs/approval-surface-adapter.md](docs/approval-surface-adapter.md): the approval-surface adapter contract.
- [docs/coding-standards.md](docs/coding-standards.md): code conventions.
- [client/SKILL.md](client/SKILL.md): how an agent connects and calls tools.
- [admin/README.md](admin/README.md): the operator control panel.

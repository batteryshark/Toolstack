---
children_hash: 0785bc7274b1774542d5e6820fce96ccc4b1287ae9b481baec799f67c5da0252
compression_ratio: 0.22481807736499426
condensation_order: 1
covers: [boundary_contracts.md, coding_standards/_index.md, component_decomposition.md, toolstack_architecture.md, toolstack_architecture_pivot.md]
covers_token_total: 5222
summary_level: d1
token_count: 1174
type: summary
---
# Toolstack Architecture d1 Overview

The Toolstack knowledge at this level converges on a single **deployment-reality architecture**: a collapsed system centered on a **Broker**, **Toolyard**, **Tool template / tool containers**, and a **nod approval adapter**. The older 9-service logical decomposition is now treated as historical context, while the canonical source of truth is rooted in **PROJECT.md** and the phased build plan in **plan.md**.

## Core architectural shift
- The old distributed service mesh has been replaced by **broker module seams** inside one process.
- Boundary contracts are only defined where there is a real **process or trust boundary**.
- The broker is the only addressable ingress for the agent; approved calls are forwarded directly to **localhost tool containers**.
- **Toolyard** is not a request proxy; it starts containers and injects **per-tool secrets at container start into tmpfs**.
- **nod** is the external approval surface, but the **broker owns approval truth**.

## Build phases and implementation direction
- The build is explicitly phased:
  - **Phase 0:** tailnet ingress + localhost-bound broker, health-only exposure
  - **Phase 1:** broker core vs stub tool
  - **Phase 2:** Toolyard + real tools + secrets-at-workload
  - **Phase 3:** approval via nod
  - **Phase 4:** admin + hardening
- The working rule across the architecture is **one component at a time**, with **fail-closed** behavior and minimal public surfaces.
- Transport, persistence, sandboxing, mTLS, queues, and other infrastructure choices are intentionally deferred until needed.

## Boundary and security model
- **`boundary_contracts.md`** defines the wire contracts across the real boundaries:
  - Agent -> Broker
  - Broker -> Tool container
  - Toolyard -> Secret backend
  - Tool container -> Toolyard
  - Broker <-> nod
- Standard outcomes include: **ok, accepted, pending_approval, denied, invalid, not_found, expired, unavailable, failed**.
- The security model emphasizes:
  - secrets live with the workload
  - broker never touches secret backends or secret material
  - arguments/results are redacted before audit or approval surfaces
  - raw tokens are never logged
  - nod titles/summaries must not contain sensitive content
- Audit taxonomy spans gateway, identity, policy, request, approval, runtime, and admin event families.

## Component relationships and ownership
- **`component_decomposition.md`** captures the physical picture:
  - tailnet ingress -> broker -> tool container
  - toolyard handles container lifecycle and secret injection
  - broker <-> nod handles approval messaging
  - toolyard -> secret backend is the only secret-path interaction
- The broker owns:
  - approval truth
  - request routing after approval
  - the only agent-reachable surface
- Toolyard owns:
  - workload secret resolution
  - container startup responsibilities
- The registry is **secret-unaware** and the broker reads tool registry data while ignoring the secrets block.

## Standards and design philosophy
- **`coding_standards/_index.md`** summarizes the implementation philosophy behind the rebuild:
  - simple, explicit, behavior-focused, transport-neutral code
  - small public surfaces
  - tests focused on behavior and boundaries
  - avoid premature commitments to infrastructure shape
- These standards underpin the architecture files and explain why the current design favors internal seams over external service boundaries.

## Historical context preserved in the architecture topic
- **`toolstack_architecture.md`** and **`toolstack_architecture_pivot.md`** preserve the transition from the older restart-point architecture to the current canonical model.
- The older plan emphasized:
  - explicit ownership boundaries
  - transport-neutral contracts
  - incremental component delivery
  - no early commitment to REST, queues, databases, sandboxing, or mTLS
- The newer pivot codifies the current operational reality:
  - broker + toolyard + tool template + approval adapter
  - Tailscale Serve as the only ingress
  - nod as the reference approval surface
  - deleted superseded docs folded into **plan.md**

## Drill-down map
- **`boundary_contracts.md`** — exact wire outcomes, audit families, redaction rules, and secret-access constraints
- **`component_decomposition.md`** — physical deployment picture, module seams, and ownership boundaries
- **`toolstack_architecture.md`** — current rebuild direction, phased build order, and canonical working rules
- **`toolstack_architecture_pivot.md`** — current architecture plus historical restart-point context
- **`coding_standards/_index.md`** — implementation philosophy and behavior-first guardrails
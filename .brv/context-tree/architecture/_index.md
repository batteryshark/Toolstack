---
children_hash: d64a2d89062614072e542754631afc0fdecd939bcfbe94a70a9886f8dd0def48
compression_ratio: 0.8587213891081295
condensation_order: 2
covers: [toolstack/_index.md]
covers_token_total: 1267
summary_level: d2
token_count: 1088
type: summary
---
# Toolstack Architecture d2 Structural Summary

## Overview
The toolstack knowledge centers on a **collapsed deployment-reality architecture** rather than the earlier 9-service logical split. The canonical model is now **Broker + Toolyard + tool containers + nod approval adapter**, with the authoritative source of truth grounded in **PROJECT.md** and the phased plan in **plan.md**.

## Core architectural model
- The system is organized around **real process and trust boundaries** only; internal seams replace the old distributed mesh.
- The **broker** is the sole agent-reachable ingress and owns:
  - approval truth
  - request routing after approval
  - forwarding approved calls directly to **localhost tool containers**
- **Toolyard** is not a proxy:
  - it starts containers
  - injects per-tool secrets at container start into **tmpfs**
  - owns workload secret resolution and container startup responsibilities
- **nod** is the external approval surface, but approval authority remains with the broker.

## Boundary, security, and contracts
- **`boundary_contracts.md`** defines the actual wire contracts at real boundaries:
  - Agent -> Broker
  - Broker -> Tool container
  - Toolyard -> Secret backend
  - Tool container -> Toolyard
  - Broker <-> nod
- Standard outcomes include:
  - `ok`, `accepted`, `pending_approval`, `denied`, `invalid`, `not_found`, `expired`, `unavailable`, `failed`
- Security rules emphasize:
  - secrets stay with the workload
  - broker never touches secret backends or secret material
  - arguments/results are redacted before audit or approval surfaces
  - raw tokens are never logged
  - nod titles/summaries must not contain sensitive content
- Audit coverage spans gateway, identity, policy, request, approval, runtime, and admin event families.

## Physical decomposition and ownership
- **`component_decomposition.md`** captures the runtime layout:
  - tailnet ingress -> broker -> tool container
  - toolyard manages container lifecycle and secret injection
  - broker <-> nod handles approval messaging
  - toolyard -> secret backend is the only secret-path interaction
- Ownership is split clearly:
  - **Broker**: ingress, approval truth, post-approval routing
  - **Toolyard**: secret resolution, container startup
  - **Registry**: secret-unaware; broker reads registry data while ignoring secret fields

## Build phases and implementation direction
- **`toolstack_architecture.md`** describes a phased build:
  - Phase 0: tailnet ingress + localhost-bound broker, health-only exposure
  - Phase 1: broker core vs stub tool
  - Phase 2: Toolyard + real tools + secrets-at-workload
  - Phase 3: approval via nod
  - Phase 4: admin + hardening
- The operating principle is:
  - one component at a time
  - fail closed
  - minimal public surfaces
- Infrastructure decisions such as transport, persistence, sandboxing, mTLS, and queues are intentionally deferred until required.

## Current pivot and historical context
- **`toolstack_architecture_pivot.md`** preserves the transition from the restart-point architecture to the current operational reality.
- The newer canonical form is:
  - broker + toolyard + tool template + approval adapter
  - Tailscale Serve as the only ingress
  - nod as the reference approval surface
  - superseded docs folded into **plan.md**
- The older architecture emphasized:
  - explicit ownership boundaries
  - transport-neutral contracts
  - incremental component delivery
  - no early commitment to REST, queues, databases, sandboxing, or mTLS

## Implementation standards
- **`coding_standards/_index.md`** provides the behavior-first engineering philosophy supporting the rebuild:
  - simple, explicit, transport-neutral code
  - small public surfaces
  - tests focused on behavior and boundaries
  - avoid premature infrastructure commitments

## Drill-down references
- **`boundary_contracts.md`** — exact wire outcomes, audit families, redaction rules, secret-access constraints
- **`component_decomposition.md`** — deployment picture, module seams, and ownership boundaries
- **`toolstack_architecture.md`** — phased rebuild direction and canonical working rules
- **`toolstack_architecture_pivot.md`** — current architecture plus historical restart-point context
- **`coding_standards/_index.md`** — implementation philosophy and behavior-first guardrails
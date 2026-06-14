---
children_hash: 1cf550874461079c930c0d84700c5490e7b9c428684c2150d9d7072fd104e254
compression_ratio: 0.8913422428820453
condensation_order: 3
covers: [architecture/_index.md, project_management/_index.md]
covers_token_total: 1721
summary_level: d3
token_count: 1534
type: summary
---
# d3 Structural Summary

## Architecture
The architecture knowledge is centered on the **collapsed deployment-reality model** documented in **architecture/_index.md**. The canonical system is now **Broker + Toolyard + tool containers + nod approval adapter**, with the source of truth grounded in **PROJECT.md** and the phased roadmap in **plan.md**.

### Core architecture
- The system is defined by **real process and trust boundaries**, not the older 9-service logical split.
- **Broker** is the only agent-reachable ingress and owns:
  - approval truth
  - routing after approval
  - forwarding approved calls directly to **localhost tool containers**
- **Toolyard** is not a proxy; it:
  - starts containers
  - injects per-tool secrets into **tmpfs** at startup
  - owns workload secret resolution and container startup
- **nod** is the external approval surface, but approval authority remains with the broker.

### Boundary contracts and security
- **boundary_contracts.md** defines the actual wire contracts at the real boundaries:
  - Agent -> Broker
  - Broker -> Tool container
  - Toolyard -> Secret backend
  - Tool container -> Toolyard
  - Broker <-> nod
- Standard outcomes include: `ok`, `accepted`, `pending_approval`, `denied`, `invalid`, `not_found`, `expired`, `unavailable`, `failed`.
- Security rules emphasize:
  - secrets stay with the workload
  - broker never touches secret backends or secret material
  - arguments/results are redacted before audit or approval surfaces
  - raw tokens are never logged
  - nod titles/summaries must not contain sensitive content
- Audit coverage spans gateway, identity, policy, request, approval, runtime, and admin event families.

### Physical decomposition and ownership
- **component_decomposition.md** captures the runtime layout:
  - tailnet ingress -> broker -> tool container
  - toolyard manages container lifecycle and secret injection
  - broker <-> nod handles approval messaging
  - toolyard -> secret backend is the only secret-path interaction
- Ownership is split clearly:
  - **Broker**: ingress, approval truth, post-approval routing
  - **Toolyard**: secret resolution, container startup
  - **Registry**: secret-unaware; broker reads registry data while ignoring secret fields

### Build phases and implementation direction
- **toolstack_architecture.md** describes the phased build:
  - Phase 0: tailnet ingress + localhost-bound broker, health-only exposure
  - Phase 1: broker core vs stub tool
  - Phase 2: Toolyard + real tools + secrets-at-workload
  - Phase 3: approval via nod
  - Phase 4: admin + hardening
- Operating principles:
  - one component at a time
  - fail closed
  - minimal public surfaces
- Transport, persistence, sandboxing, mTLS, and queues are intentionally deferred until needed.

### Pivot and historical context
- **toolstack_architecture_pivot.md** preserves the transition from the restart-point architecture to the current operational reality.
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

### Implementation standards
- **coding_standards/_index.md** provides the supporting engineering philosophy:
  - simple, explicit, transport-neutral code
  - small public surfaces
  - behavior- and boundary-focused tests
  - avoid premature infrastructure commitments

## Project Management
The project management knowledge in **project_management/_index.md** is the rebuild record for the Toolstack effort. It documents the timeline, pivot, and the current next step.

### Scope and purpose
- Captures rebuild progress, verification status, cleanup actions, and the current direction.
- Serves as the historical record for decisions that shaped the Toolstack architecture.

### Major phases
- **2026-05-27 rebuild kickoff**: greenfield Toolstack rebuild began and initial artifacts were recorded.
- **2026-06-13 pivot review**: architecture collapsed toward deployment reality, replacing the older **ClientProfileService-first decomposition** with **Phase 0 boundary work**.
- **Current direction**: **Phase 0** is the next step, centered on **tailnet ingress** and a **localhost-only broker**.

### Key preserved facts
- Rebuild start date: **2026-05-27**
- Pivot date: **2026-06-13**
- Deleted during pivot: **docs/component-plans.md** and **docs/component-io-contracts.md**
- Current next step: **Phase 0: tailnet ingress plus a localhost-only broker**

### Architectural relationships and constraints
- The work log ties back to the canonical architecture sources in **architecture/toolstack.md** and **architecture/toolstack/toolstack_architecture.md**.
- It preserves both the superseded service decomposition and the newer collapsed **broker/toolyard** design.
- Superseded 2026-05-27 rules (these named services no longer exist as separate processes — they collapsed into broker module seams; kept only as history):
  - BrokerGateway/RequestService/ToolRegistryService must not talk directly to SecretsManagementService.
  - SecretsManagementService owned namespaces and component-to-component credentials.
  - Approvals routed through a separate Approval Surface Endpoint.
- Still current (carried forward as invariants): the registry is secret-unaware and the broker is never on the secret path — now enforced physically, since the broker reads toolyard.yaml and ignores the secrets block.

### Drill-down references
- **architecture/_index.md** — canonical architecture summary and key boundaries
- **boundary_contracts.md** — wire outcomes, redaction rules, audit families, secret-access constraints
- **component_decomposition.md** — deployment picture, module seams, ownership boundaries
- **toolstack_architecture.md** — phased rebuild direction and operating rules
- **toolstack_architecture_pivot.md** — current architecture plus historical restart-point context
- **coding_standards/_index.md** — implementation philosophy and behavior-first guardrails
- **context.md** — concise topic overview and relations
- **work_log.md** — full rebuild history, raw concept, narrative, and facts
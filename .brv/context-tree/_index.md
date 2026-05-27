---
children_hash: 804199770fe59b5916f279cf4615ea66bb6131a05a850a69887eb21f7ad002e1
compression_ratio: 0.8367729831144465
condensation_order: 3
covers: [architecture/_index.md, project_management/_index.md]
covers_token_total: 2132
summary_level: d3
token_count: 1784
type: summary
---
# d3 Structural Summary

## Architecture: Toolstack rebuild posture and component boundaries
The architecture entry set describes a **greenfield Toolstack rebuild** restarted from **`PROJECT.md`**, with implementation intentionally sequenced **one component at a time**. The system is designed to remain **transport-neutral** until each component needs a concrete choice, delaying commitments such as REST, queues, databases, sandboxing, mTLS, and deployment shape.

### Core architecture entries
- **`toolstack_architecture.md`** — project-wide rebuild posture, restart rules, and architectural direction.
- **`coding_standards.md`** — implementation discipline: explicit code, small public surfaces, behavior-focused tests, and no premature infrastructure.
- **`component_decomposition.md`** / **`component_design.md`** — trust zones and ownership layout.
- **`component_io_contracts.md`** — service boundaries, allowed inputs/outputs, and forbidden interactions.
- **`message_contracts.md`** — transport-neutral message envelope and routing rules.
- **`component_plans.md`** — build order, scope limits, and do-not-build constraints.

### Rebuild posture and implementation discipline
The rebuild is framed as a controlled restart with strong restraint:
- build **one component at a time**
- prefer **boring, explicit code**
- keep interfaces small
- test **behavior and boundaries**, not transport internals
- avoid premature infrastructure decisions

These rules support readability, isolation, and incremental validation.

## Component decomposition and trust zones
The component model divides the system into clear trust zones:

**external client zone → gateway → request orchestration → approval / runtime / secrets / event logging**

### Key ownership boundaries
- **BrokerGateway**: normal entry point for client actions
- **ClientProfileService**: supports gateway interactions
- **RequestService**: owns mutable request lifecycle state and orchestrates core flows
- **PolicyService**: governs request decisions
- **ToolRegistryService**: metadata-only registry, no secret awareness
- **ApprovalService** / **Approval Surface Endpoint**: handle approval flows outside the gateway path
- **ToolRuntimeService**: executes runtime actions and materializes secrets through secrets services
- **SecretsManagementService**: owns workload secrets and component-to-component credentials
- **EventLoggingService**: append-only audit/event history
- **Control Panel**: admin interface over domain services

### Boundary rules that recur across entries
- **BrokerGateway** only talks to **ClientProfileService** and **RequestService**
- **BrokerGateway**, **RequestService**, and **ToolRegistryService** must not access secrets directly
- **ToolRegistryService** must not declare secret namespaces, secret keys, or secret requirements
- **EventLoggingService** receives redacted events and does not own mutable request state

## Service I/O contracts and message layer
`component_io_contracts.md` and `message_contracts.md` form the boundary layer between services.

### I/O contract themes
- each service has explicit consumes / produces / must-not rules
- secret values must not leak into logs or public payloads
- authorization, secrets, orchestration, and event logging remain separated

### Important service constraints
- **RequestService** consumes authenticated request context, policy decisions, tool metadata, approval outcomes, and runtime results; it must not call **SecretsManagementService** or authenticate raw profile tokens
- **BrokerGateway** must not directly call **PolicyService**, **ToolRegistryService**, **ApprovalService**, **ToolRuntimeService**, or **SecretsManagementService**
- **ClientProfileService** must not decide tool authorization or expose raw tokens
- **ToolRegistryService** remains metadata-only
- **ApprovalService** must not decide initial authorization or include raw secrets in prompts
- **ToolRuntimeService** handles secret materialization but not authorization
- **EventLoggingService** must not own mutable request state or make authorization decisions

### Message contract structure
`message_contracts.md` defines a shared transport-neutral envelope with:
- `message_id`
- `correlation_id`
- `source_component`
- `target_component`
- `issued_at`

Standard outcomes include:
- `ok`, `accepted`, `pending_approval`, `denied`, `invalid`, `not_found`, `expired`, `unavailable`, `failed`

Captured message families include:
- external client messages
- orchestration messages
- approval messages
- runtime messages
- secrets messages
- admin messages
- event logging messages

Representative messages mentioned in the entry set include:
- `ClientActionRequest`
- `AuthenticateProfileToken`
- `SubmitRequest`
- `MaterializeWorkloadSecrets`
- `AppendAuditEvent`

## Component build plan
`component_plans.md` turns the architecture into a staged rollout with explicit exclusions.

### Planned build order
**ClientProfileService → event logging → registry → policy → request → approval → secrets → runtime → gateway → control panel**

### Planning structure
Each planned component is described with:
- a **goal**
- a **build list**
- a **do-not-build list**

This prevents scope creep and preserves the intended isolation of policy, secrets, and transport concerns.

### Notable plan constraints
- **ClientProfileService** is first
- **EventLoggingService** provides append-only audit events
- **ToolRegistryService** catalogs tools and operations without secret awareness
- **Control Panel** is last and stays admin-only without owning primary state

## Project management: Work log and rebuild tracking
The project management entry set records the **2026-05-27 restart** of the Toolstack rebuild and the shift away from the removed all-in-one scaffold toward isolated component delivery.

### Core work log themes
- rebuild history and progress tracking
- verification and cleanup after distilling rules into local docs
- incremental build sequencing instead of monolithic rollout

### Key decisions preserved in the work log
- the prior **all-in-one scaffold was intentionally removed**
- the next likely implementation step is **ClientProfileService**
- **BrokerGateway**, **RequestService**, and **ToolRegistryService** must not talk directly to **SecretsManagementService**
- **ToolRegistryService** has no secret awareness
- **SecretsManagementService** owns workload namespaces and component-to-component credentials
- approval flows must route through an **external Approval Surface Endpoint**

## Cross-entry relationships
- **`toolstack_architecture.md`** sets the restart posture and project-level rules.
- **`coding_standards.md`** constrains how implementation proceeds.
- **`component_decomposition.md`** and **`component_design.md`** define ownership, zones, and orchestration.
- **`component_io_contracts.md`** and **`message_contracts.md`** formalize service boundaries and transport-neutral communication.
- **`component_plans.md`** enforces the rollout sequence that preserves the architecture.
- **`work_log.md`** records the live rebuild state, cleanup decisions, and next step.
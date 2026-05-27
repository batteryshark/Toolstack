---
children_hash: 1ec9d0854de296b05c72d0af507e04aa8fc74cd5fbb57f4ca93777b7d68095e8
compression_ratio: 0.8563096500530223
condensation_order: 2
covers: [toolstack/_index.md]
covers_token_total: 1886
summary_level: d2
token_count: 1615
type: summary
---
# Toolstack d2 Structural Summary

## Architecture posture and rebuild strategy
The Toolstack knowledge base describes a **greenfield, pre-implementation rebuild** that restarts from **`PROJECT.md`** and proceeds **one component at a time**. The architecture is intentionally **transport-neutral**, deferring choices such as REST, queues, databases, sandboxing, mTLS, and deployment shape until each component requires them.

**Drill down:** `toolstack_architecture.md`

## Implementation standards
**`coding_standards.md`** sets the rebuild discipline:
- Build **one component at a time**
- Prefer **boring, explicit code** over clever abstractions
- Keep **public surfaces small**
- Test **behavior and boundaries**, not transport details or internals
- Avoid premature infrastructure commitments

These standards reinforce readability, narrow interfaces, and component isolation.

**Drill down:** `coding_standards.md`

## Component decomposition and trust zones
**`component_decomposition.md`** and **`component_design.md`** organize the system into explicit trust zones:

**external client zone → gateway → request orchestration → approval / runtime / secrets / event logging**

### Main component ownership
- **BrokerGateway**: normal entry point for client actions
- **ClientProfileService**: supports gateway interactions
- **RequestService**: owns mutable request lifecycle state and orchestrates core flows
- **PolicyService**: governs request decisions
- **ToolRegistryService**: metadata-only registry with no secret awareness
- **ApprovalService** / **Approval Surface Endpoint**: handle approval flows externally from the gateway path
- **ToolRuntimeService**: executes runtime actions and materializes secrets via the secrets service
- **SecretsManagementService**: owns workload secrets and component-to-component credentials
- **EventLoggingService**: owns append-only audit/event history
- **Control Panel**: admin interface over domain services

### Boundary rules
- **BrokerGateway** only talks to **ClientProfileService** and **RequestService**
- **BrokerGateway**, **RequestService**, and **ToolRegistryService** have **no direct secret path**
- **ToolRegistryService** must not declare secret namespaces, secret keys, or secret requirements
- **EventLoggingService** receives redacted events and does not own mutable request state

**Drill down:** `component_decomposition.md`, `component_design.md`

## Component I/O contracts
**`component_io_contracts.md`** defines explicit consume/produce boundaries and “must-not” rules for each service.

### Core contract themes
- Each service has explicit inputs, outputs, and forbidden interactions
- Secret values must not leak into logs or public payloads
- Authorization, secret handling, orchestration, and event logging remain separated

### Key constraints
- **RequestService** consumes authenticated request context, policy decisions, tool metadata, approval outcomes, and runtime results; it must not call **SecretsManagementService** or authenticate raw profile tokens
- **BrokerGateway** must not directly call **PolicyService**, **ToolRegistryService**, **ApprovalService**, **ToolRuntimeService**, or **SecretsManagementService**
- **ClientProfileService** must not decide tool authorization or expose raw tokens
- **ToolRegistryService** is metadata-only
- **ApprovalService** must not decide initial tool authorization or include raw secrets in prompts
- **ToolRuntimeService** handles secret materialization, but not authorization
- **EventLoggingService** must not own mutable request state or make authorization decisions

This document pairs with **`message_contracts.md`** as the service-boundary layer complement.

**Drill down:** `component_io_contracts.md`

## Message contracts
**`message_contracts.md`** defines the transport-neutral message layer shared across request, approval, runtime, admin, secrets, and event logging flows.

### Message structure
Shared envelope fields:
- `message_id`
- `correlation_id`
- `source_component`
- `target_component`
- `issued_at`

Standard outcomes:
- `ok`
- `accepted`
- `pending_approval`
- `denied`
- `invalid`
- `not_found`
- `expired`
- `unavailable`
- `failed`

### Message families
- external client messages
- orchestration messages
- approval messages
- runtime messages
- secrets messages
- admin messages
- event logging messages

### Security and routing rules
- Secret values must not appear in request, approval, registry, policy, or audit payloads except as redacted metadata
- **BrokerGateway** only talks to **ClientProfileService** and **RequestService**
- **ToolRegistryService** has no secret awareness
- Approval surfaces are external and communicate through the **Approval Surface Endpoint**
- **RequestService** owns mutable request state
- **EventLoggingService** owns append-only audit/event history

Captured message examples include:
- `ClientActionRequest`
- `AuthenticateProfileToken`
- `SubmitRequest`
- `MaterializeWorkloadSecrets`
- `AppendAuditEvent`

**Drill down:** `message_contracts.md`

## Component build plan
**`component_plans.md`** turns the architecture into an implementation sequence with explicit scope limits.

### Planned build order
**ClientProfileService → event logging → registry → policy → request → approval → secrets → runtime → gateway → control panel**

### Planning structure
Each component section includes:
- a **goal**
- a **build list**
- a **do-not-build list**

This prevents scope creep and premature coupling, especially around secrets, policy, and transport concerns.

### Notable planning facts
- **ClientProfileService** is the first planned component
- **EventLoggingService** should provide append-only audit events
- **ToolRegistryService** should catalog tools and operations without secret awareness
- **Control Panel** comes last and should provide admin workflows without owning primary state

**Drill down:** `component_plans.md`

## Cross-entry relationship
- **`toolstack_architecture.md`** defines the restart-point posture and project-level rules.
- **`coding_standards.md`** defines implementation discipline.
- **`component_decomposition.md`** and **`component_design.md`** define trust zones, ownership, and orchestration layout.
- **`component_io_contracts.md`** and **`message_contracts.md`** define service boundaries and transport-neutral message rules.
- **`component_plans.md`** defines the build order and exclusions that preserve the architecture.
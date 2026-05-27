---
children_hash: e878bd37a842868b27cf180d77c03c0f659094e19062512a96f4d639fb272af4
compression_ratio: 0.3509644064426327
condensation_order: 1
covers: [coding_standards/_index.md, component_decomposition/_index.md, component_design/_index.md, component_io_contracts/_index.md, component_plans/_index.md, context.md, message_contracts/_index.md, toolstack_architecture.md, toolstack_architecture/_index.md]
covers_token_total: 5029
summary_level: d1
token_count: 1765
type: summary
---
# Toolstack d1 Structural Summary

## Architecture and rebuild posture
The Toolstack knowledge base describes a **greenfield, pre-implementation rebuild** that starts from a restart point in **`PROJECT.md`** and proceeds **one component at a time**. The system is intentionally **transport-neutral** and defers choices like REST, queues, databases, sandboxing, mTLS, and deployment shape until a specific component needs them.

### Core architectural direction
- Favor **isolated components** with explicit ownership boundaries and small public surfaces.
- Keep implementation **boring, explicit, and behavior-focused**.
- Test behavior and boundaries rather than transport details or incidental internals.

See **`toolstack_architecture.md`** for the restart-state overview and the project-level rules.

## Implementation standards
The standards in **`coding_standards.md`** act as guardrails for the rebuild:
- Build **one component at a time**
- Prefer **boring, explicit code** over clever abstractions
- Keep **public surfaces small**
- Keep tests focused on **behavior and boundaries**
- Avoid premature commitment to infrastructure decisions

These standards reinforce readability, narrow interfaces, and component isolation.

## Component decomposition and trust zones
The decomposition in **`component_decomposition.md`** and **`component_design.md`** organizes the system into explicit trust zones:

**external client zone → gateway → request orchestration → approval / runtime / secrets / event logging**

### Main components and ownership
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

### Key boundary rules
- **BrokerGateway** only talks to **ClientProfileService** and **RequestService**
- **BrokerGateway**, **RequestService**, and **ToolRegistryService** have **no direct secret path**
- **ToolRegistryService** must not declare secret namespaces, secret keys, or secret requirements
- **EventLoggingService** receives redacted events and does not own mutable request state

Refer to **`component_decomposition.md`** for the full trust-zone model and **`component_design.md`** for the control-plane orchestration view.

## Component I/O contracts
**`component_io_contracts.md`** defines consume/produce boundaries and the “must-not” rules for each service.

### Core contract themes
- Each service has explicit inputs, outputs, and forbidden interactions
- Secret values must not leak into logs or public payloads
- Authorization, secret handling, orchestration, and event logging remain separated cleanly

### Notable contract constraints
- **RequestService** consumes authenticated request context, policy decisions, tool metadata, approval outcomes, and runtime results; it must not call **SecretsManagementService** or authenticate raw profile tokens
- **BrokerGateway** is constrained from directly calling **PolicyService**, **ToolRegistryService**, **ApprovalService**, **ToolRuntimeService**, or **SecretsManagementService**
- **ClientProfileService** must not decide tool authorization or expose raw tokens
- **ToolRegistryService** is metadata-only
- **ApprovalService** must not decide initial tool authorization or include raw secrets in prompts
- **ToolRuntimeService** handles secret materialization, but not authorization
- **EventLoggingService** must not own mutable request state or make authorization decisions

This document aligns with **`message_contracts.md`** as the message-layer complement to I/O boundaries.

## Message contracts
**`message_contracts.md`** defines the transport-neutral message layer shared across request, approval, runtime, admin, secrets, and event logging flows.

### Core structure
- Shared envelope fields: `message_id`, `correlation_id`, `source_component`, `target_component`, `issued_at`
- Standard outcomes include: `ok`, `accepted`, `pending_approval`, `denied`, `invalid`, `not_found`, `expired`, `unavailable`, `failed`
- Message families cover:
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

Key message examples captured include:
- `ClientActionRequest`
- `AuthenticateProfileToken`
- `SubmitRequest`
- `MaterializeWorkloadSecrets`
- `AppendAuditEvent`

## Component build plan
The roadmap in **`component_plans.md`** defines the intended implementation order and scope limits.

### Build sequence
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

## Overall relationship between the entries
- **`toolstack_architecture.md`** defines the restart-point posture and project-level rules.
- **`coding_standards.md`** defines implementation discipline.
- **`component_decomposition.md`** and **`component_design.md`** define trust zones, component ownership, and orchestration layout.
- **`component_io_contracts.md`** and **`message_contracts.md`** define service boundaries and transport-neutral message rules.
- **`component_plans.md`** turns the architecture into a build order with explicit exclusions.

## Drill-down references
- **`coding_standards.md`**
- **`component_decomposition.md`**
- **`component_design.md`**
- **`component_io_contracts.md`**
- **`component_plans.md`**
- **`message_contracts.md`**
- **`toolstack_architecture.md`**

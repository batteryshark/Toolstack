---
children_hash: 7cd8d70e5e725fb8e7556c8f28170cecb88d9f97cb32868750a24e730c3c65e0
compression_ratio: 0.9962962962962963
condensation_order: 0
covers: [component_i_o_contracts.md]
covers_token_total: 810
summary_level: d0
token_count: 807
type: summary
---
# Structural Overview: Toolstack Component I/O Contracts

## Scope
`component_i_o_contracts.md` defines the consume/produce boundaries for the toolstack components and makes explicit what each service owns, emits, and must not do. It is built on `component_decomposition.md` as the source of truth for allowed relationships, and it aligns with `message_contracts.md` for request/response shape and trust-boundary handling.

## Core Structure
The document is organized into:
- a summary table of all components,
- per-component I/O contracts,
- zone-level contracts separating:
  - external client,
  - control plane,
  - runtime,
  - secrets,
  - event logging.

The overall flow is:

**consume request inputs -> produce component-specific outputs -> preserve redaction and ownership boundaries**

## Key Architectural Decisions
- Trust boundaries are explicit and enforced through must-not rules.
- Secret values must not leak into logs or public payloads.
- Component responsibilities are separated so authorization, secret handling, orchestration, and event logging do not overlap incorrectly.

## Component Boundary Highlights
### Request and orchestration path
- `RequestService` consumes authenticated request context, policy decisions, tool metadata, approval outcomes, and runtime results.
- It produces request state, orchestration commands, and lifecycle events.
- It must not call `SecretsManagementService` or authenticate raw profile tokens.

### Gateway boundary
- `BrokerGateway` is constrained from directly calling:
  - `SecretsManagementService`
  - `PolicyService`
  - `ToolRegistryService`
  - `ApprovalService`
  - `ToolRuntimeService`

### Client/profile boundary
- `ClientProfileService` must not decide tool authorization or expose raw tokens.

### Registry boundary
- `ToolRegistryService` is metadata-only.
- It must not declare secret namespaces, secret keys, or secret requirements.
- This matches the fact that registry contracts contain metadata only and no secret fields.

### Approval boundary
- `ApprovalService` must not decide initial tool authorization or include raw secrets in prompts.
- Approval surfaces are external and must communicate through the **Approval Surface Endpoint**.

### Runtime boundary
- `ToolRuntimeService` must not decide authorization or expose raw secret material.
- It is responsible for workload secret materialization from `SecretsManagementService`.

### Secrets and event logging
- `SecretsManagementService` must not receive direct requests from:
  - `BrokerGateway`
  - `RequestService`
  - `ToolRegistryService`
- `EventLoggingService` must not own mutable request lifecycle state or make authorization decisions.

## Key Facts
- `BrokerGateway` has strict call restrictions against core control-plane and runtime services.
- `ToolRegistryService` is metadata-only with no secret fields.
- Approval interactions are externalized through the Approval Surface Endpoint.
- `ToolRuntimeService` handles secret materialization, but not authorization.
- The contracts preserve the rule that secret material must remain out of logs and public payloads.

## Drill-Down Entry
- `component_i_o_contracts.md` — detailed consume/produce tables and per-service must-not rules.
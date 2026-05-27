---
title: Component I/O Contracts
summary: Component I/O contracts define what each service consumes, produces, owns, and must not do.
tags: []
related: [architecture/toolstack/component_design.md, architecture/toolstack/message_contracts.md, architecture/toolstack/component_decomposition/component_decomposition.md, architecture/toolstack/message_contracts/message_contracts.md]
keywords: []
createdAt: '2026-05-27T16:36:15.536Z'
updatedAt: '2026-05-27T16:52:46.208Z'
---
## Reason
Capture the logical consume/produce boundaries for each component

## Raw Concept
**Task:**
Document component consume/produce contracts for the toolstack

**Changes:**
- Defined summary table of component inputs and outputs
- Specified must-not rules for each component
- Defined a summary table for all components
- Separated external client, control plane, runtime, secrets, and monitoring zones

**Files:**
- docs/component-io-contracts.md
- docs/component-decomposition.md
- docs/message-contracts.md

**Flow:**
consume request inputs -> produce component-specific outputs -> preserve redaction and ownership boundaries

**Timestamp:** 2026-05-27T16:51:34.761Z

## Narrative
### Structure
The document is organized into a summary table, per-component contracts, and zone-level contracts.

### Dependencies
These I/O contracts depend on the component decomposition as the source of truth for allowed relationships.

### Highlights
The contracts make the trust boundaries explicit and preserve the rule that secret values must not leak into logs or public payloads.

### Rules
BrokerGateway must not call SecretsManagementService, PolicyService, ToolRegistryService, ApprovalService, or ToolRuntimeService directly. ClientProfileService must not decide tool authorization or expose raw tokens. RequestService must not call SecretsManagementService or authenticate raw profile tokens. ToolRegistryService must not declare secret namespaces, secret keys, or secret requirements. ApprovalService must not decide initial tool authorization or include raw secrets in prompts. ToolRuntimeService must not decide authorization or expose raw secret material. SecretsManagementService must not receive direct requests from BrokerGateway, RequestService, or ToolRegistryService. ToolMonitoringService must not own mutable request lifecycle state or make authorization decisions.

### Examples
The summary table lists each component’s consumes and produces, such as RequestService consuming authenticated request context, policy decisions, tool metadata, approval outcomes, and runtime results while producing request state, orchestration commands, and lifecycle events.

## Facts
- **broker_gateway_must_not_call**: BrokerGateway must not call SecretsManagementService, PolicyService, ToolRegistryService, ApprovalService, or ToolRuntimeService directly. [convention]
- **registry_contract_rule**: ToolRegistryService contracts contain metadata only and no secret fields. [convention]
- **approval_boundary**: Approval surfaces are external and must communicate through the Approval Surface Endpoint. [convention]
- **runtime_secret_materialization**: ToolRuntimeService is responsible for workload secret materialization from SecretsManagementService. [project]

---
title: Component Decomposition
summary: Component decomposition defines agents, admin, core control plane, approval, runtime, secrets, and monitoring zones with explicit ownership boundaries.
tags: []
related: [architecture/toolstack.md, architecture/toolstack/component_io_contracts.md, architecture/toolstack/message_contracts.md]
keywords: []
createdAt: '2026-05-27T16:36:15.535Z'
updatedAt: '2026-05-27T16:36:15.535Z'
---
## Reason
Capture the component diagram, zones, and threat-model-oriented ownership boundaries

## Raw Concept
**Task:**
Document the component decomposition and trust-zone layout

**Changes:**
- Added a threat-model-oriented component diagram
- Defined core control plane and external trust zones

**Files:**
- docs/component-decomposition.md

**Flow:**
external agent/client -> gateway -> request orchestration -> approval/runtime/secrets/monitoring

**Timestamp:** 2026-05-27

## Narrative
### Structure
The diagram separates External Agent / Client, Admin Operator, Core Control Plane, External Approval Surface, Tool Runtime, Secrets, and Monitoring trust zones.

### Dependencies
BrokerGateway is limited to ClientProfileService and RequestService; RequestService coordinates with PolicyService, ToolRegistryService, ApprovalService, and ToolRuntimeService; SecretsManagementService serves runtime and approved internal components; Monitoring receives redacted events from every domain.

### Highlights
ToolRegistryService has no secret awareness, ToolMonitoringService is append-only, and SecretsManagementService owns both workload secrets and component-to-component credentials.

### Rules
BrokerGateway is the only normal entry point for agent/client action requests. Approval Surface Endpoint is a separate external boundary. ToolRegistryService never declares secret namespaces, secret keys, or secret requirements. ToolRuntimeService asks for secrets using the active profile/tool execution context. ToolMonitoringService receives events from every domain but does not own mutable request state.

### Examples
A client action request enters through BrokerGateway, gets authenticated by ClientProfileService, is submitted to RequestService, then may flow to PolicyService, ApprovalService, ToolRuntimeService, and ToolMonitoringService as needed.

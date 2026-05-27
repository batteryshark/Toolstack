---
title: Component Decomposition
summary: Component decomposition defines the isolated services, their trust boundaries, and their allowed interactions.
tags: []
related: [architecture/toolstack/component_io_contracts/component_i_o_contracts.md, architecture/toolstack/message_contracts/message_contracts.md]
keywords: []
createdAt: '2026-05-27T16:52:46.206Z'
updatedAt: '2026-05-27T16:52:46.206Z'
---
## Reason
Capture the component boundaries and ownership model

## Raw Concept
**Task:**
Document the toolstack component decomposition and ownership boundaries

**Changes:**
- Defined component boundaries
- Captured allowed and forbidden direct relationships
- Separated trust zones

**Files:**
- docs/component-decomposition.md
- docs/component-io-contracts.md
- docs/message-contracts.md

**Flow:**
external client zone -> gateway -> request orchestration -> approval/runtime/secrets/event logging zones

**Timestamp:** 2026-05-27T16:51:34.761Z

## Narrative
### Structure
The decomposition organizes the system into BrokerGateway, ClientProfileService, RequestService, PolicyService, ToolRegistryService, ApprovalService, Approval Surface Endpoint, ToolRuntimeService, SecretsManagementService, EventLoggingService, and Control Panel.

### Dependencies
The architecture enforces trust-zone separation so secrets, approvals, runtime, and event logging remain independent services with narrow contracts.

### Highlights
The design is intentionally boring and explicit, with clear ownership and no direct secret path from BrokerGateway, RequestService, or ToolRegistryService.

## Facts
- **broker_gateway_allowed_peers**: BrokerGateway only talks to ClientProfileService and RequestService. [convention]
- **request_ownership**: RequestService owns mutable request lifecycle state. [convention]
- **event_logging_ownership**: EventLoggingService owns append-only audit/event history. [convention]
- **registry_secret_awareness**: ToolRegistryService has no secret awareness. [convention]
- **secrets_ownership**: SecretsManagementService owns secret namespaces and component-to-component credentials. [project]

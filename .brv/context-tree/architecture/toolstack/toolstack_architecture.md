---
title: Toolstack Architecture
summary: Toolstack is a greenfield agentic tool management system with explicit component boundaries and transport-neutral contracts.
tags: []
related: [architecture/toolstack/component_design.md, architecture/toolstack/component_io_contracts.md, architecture/toolstack/message_contracts.md, architecture/toolstack/coding_standards.md]
keywords: []
createdAt: '2026-05-27T16:36:15.530Z'
updatedAt: '2026-05-27T16:36:15.530Z'
---
## Reason
Document the Toolstack rebuild architecture, ownership boundaries, and component relationships

## Raw Concept
**Task:**
Document the overall Toolstack rebuild architecture and operational rules

**Changes:**
- Established a restart point in PROJECT.md
- Defined component decomposition, IO contracts, message contracts, coding standards, and work log
- Removed the all-in-one scaffold and kept the next recommended component

**Files:**
- PROJECT.md
- docs/component-decomposition.md
- docs/component-io-contracts.md
- docs/message-contracts.md
- docs/coding-standards.md
- docs/work-log.md
- docs/component-plans.md

**Flow:**
project restart -> define boundaries -> define IO contracts -> define message contracts -> remove all-in-one scaffold -> build next component

**Timestamp:** 2026-05-27

## Narrative
### Structure
The project is organized around a central PROJECT.md restart point plus supporting docs for decomposition, IO contracts, message contracts, coding standards, plans, and work history.

### Dependencies
The architecture depends on transport-neutral contracts and explicit ownership boundaries before persistent storage or transport choices are made.

### Highlights
The build strategy is intentionally incremental: one component at a time, with ultra-simple code and focused tests on behavior and boundaries.

### Rules
Build one component at a time. Prefer boring, explicit code over clever abstractions. Keep public surfaces small. Keep tests focused on behavior and boundaries. Do not choose REST, queues, databases, sandboxing, mTLS, or deployment shape until a component actually needs that decision. Do not let `BrokerGateway`, `RequestService`, or `ToolRegistryService` talk directly to `SecretsManagementService`. Do not let `ToolRegistryService` know secret namespaces, secret keys, or secret requirements.

### Examples
There is no active implementation or test suite after removing the all-in-one scaffold. Start with ClientProfileService as the next component.

## Facts
- **project_type**: Toolstack is a greenfield agentic tool management project. [project]
- **source_of_truth**: The source of truth starts at PROJECT.md. [project]
- **current_status**: The all-in-one scaffold was removed. The repo is in pre-implementation planning state and ready for the first isolated component. [project]
- **next_step**: The next recommended component is ClientProfileService. [project]
- **broker_gateway_connections**: BrokerGateway only talks to ClientProfileService and RequestService. [convention]
- **secrets_boundary**: BrokerGateway, RequestService, and ToolRegistryService must not call SecretsManagementService. [convention]
- **tool_registry_secret_awareness**: ToolRegistryService has no secret awareness. [convention]
- **secrets_ownership**: SecretsManagementService owns workload namespaces plus component-to-component credentials. [project]
- **request_ownership**: RequestService owns mutable request lifecycle. [project]
- **event_logging_ownership**: EventLoggingService owns append-only audit history. [project]

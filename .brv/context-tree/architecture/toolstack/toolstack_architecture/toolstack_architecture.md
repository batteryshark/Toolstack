---
title: Toolstack Architecture
summary: Toolstack rebuild is reset to a one-component-at-a-time, transport-neutral architecture with no active implementation yet.
tags: []
related: [architecture/toolstack/coding_standards/coding_standards.md, architecture/toolstack/component_design/component_decomposition.md, architecture/toolstack/component_io_contracts/component_i_o_contracts.md, architecture/toolstack/message_contracts/message_contracts.md]
keywords: []
createdAt: '2026-05-27T16:52:46.198Z'
updatedAt: '2026-05-27T16:52:46.198Z'
---
## Reason
Capture the project restart point and core architecture rules

## Raw Concept
**Task:**
Document the restart-point architecture for the Toolstack rebuild

**Changes:**
- Removed the earlier all-in-one scaffold
- Reset the repo to a pre-implementation planning state
- Recorded the next suggested isolated component

**Files:**
- PROJECT.md
- docs/component-decomposition.md
- docs/component-io-contracts.md
- docs/message-contracts.md
- docs/coding-standards.md
- docs/component-plans.md
- docs/work-log.md
- .brv/config.json

**Flow:**
project restart -> architecture docs define boundaries -> build one component -> add focused tests

**Timestamp:** 2026-05-27T16:51:34.761Z

## Narrative
### Structure
PROJECT.md now serves as the nerve center and links to the architecture, coding standards, component plans, and work log documents.

### Dependencies
The architecture intentionally stays transport-neutral and postpones deployment and infrastructure decisions until needed by a specific component.

### Highlights
The system is deliberately simplified into isolated components with explicit ownership boundaries and small public surfaces.

### Rules
Build one component at a time.
Prefer boring, explicit code over clever abstractions.
Keep public surfaces small.
Keep tests focused on behavior and boundaries.
Do not choose REST, queues, databases, sandboxing, mTLS, or deployment shape until a component actually needs that decision.
Do not let BrokerGateway, RequestService, or ToolRegistryService talk directly to SecretsManagementService.
Do not let ToolRegistryService know secret namespaces, secret keys, or secret requirements.

## Facts
- **repo_state**: The repo is in a pre-implementation state and the restart point is PROJECT.md. [project]
- **build_strategy**: The build strategy is one component at a time. [convention]
- **architecture_decision_timing**: The project should avoid choosing REST, queues, databases, sandboxing, mTLS, or deployment shape until a component needs that decision. [convention]
- **implementation_status**: There is no active source implementation or test suite until the first isolated component is created. [project]
- **next_component**: The next recommended component is ClientProfileService. [project]
- **brv_cwd**: .brv/config.json was made path-agnostic by changing cwd from an absolute local path to dot. [project]

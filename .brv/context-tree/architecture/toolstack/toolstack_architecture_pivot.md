---
title: Toolstack Architecture Pivot
summary: Canonical toolstack architecture now reflects deployment reality with Broker, Toolyard, Tool template, and Approval adapter; older restart-point decomposition is preserved as historical context.
tags: []
related: [architecture/toolstack/component_decomposition.md, architecture/toolstack/message_contracts.md, architecture/toolstack/approval_surface_adapter.md, architecture/toolstack/coding_standards.md, architecture/toolstack/context.md]
keywords: []
createdAt: '2026-06-14T03:58:47.301Z'
updatedAt: '2026-06-14T03:58:47.301Z'
consolidated_at: '2026-06-14T04:07:10.814Z'
consolidated_from: [{date: '2026-06-14T04:07:10.814Z', path: architecture/toolstack/context.md, reason: 'These files describe the same toolstack topic across abstract, narrative, overview, and pivot forms. The pivot is the richer and newer canonical statement, while the existing architecture files and summaries are overlapping context that should be consolidated into one coherent topic with temporal framing for the older restart-point architecture and the newer deployment-reality pivot.'}, {date: '2026-06-14T04:07:10.814Z', path: architecture/toolstack/toolstack_architecture.abstract.md, reason: 'These files describe the same toolstack topic across abstract, narrative, overview, and pivot forms. The pivot is the richer and newer canonical statement, while the existing architecture files and summaries are overlapping context that should be consolidated into one coherent topic with temporal framing for the older restart-point architecture and the newer deployment-reality pivot.'}, {date: '2026-06-14T04:07:10.814Z', path: architecture/toolstack/toolstack_architecture.md, reason: 'These files describe the same toolstack topic across abstract, narrative, overview, and pivot forms. The pivot is the richer and newer canonical statement, while the existing architecture files and summaries are overlapping context that should be consolidated into one coherent topic with temporal framing for the older restart-point architecture and the newer deployment-reality pivot.'}, {date: '2026-06-14T04:07:10.814Z', path: architecture/toolstack/toolstack_architecture.overview.md, reason: 'These files describe the same toolstack topic across abstract, narrative, overview, and pivot forms. The pivot is the richer and newer canonical statement, while the existing architecture files and summaries are overlapping context that should be consolidated into one coherent topic with temporal framing for the older restart-point architecture and the newer deployment-reality pivot.'}, {date: '2026-06-14T04:07:10.814Z', path: architecture/toolstack/toolstack_architecture_pivot.abstract.md, reason: 'These files describe the same toolstack topic across abstract, narrative, overview, and pivot forms. The pivot is the richer and newer canonical statement, while the existing architecture files and summaries are overlapping context that should be consolidated into one coherent topic with temporal framing for the older restart-point architecture and the newer deployment-reality pivot.'}, {date: '2026-06-14T04:07:10.814Z', path: architecture/toolstack/toolstack_architecture_pivot.overview.md, reason: 'These files describe the same toolstack topic across abstract, narrative, overview, and pivot forms. The pivot is the richer and newer canonical statement, while the existing architecture files and summaries are overlapping context that should be consolidated into one coherent topic with temporal framing for the older restart-point architecture and the newer deployment-reality pivot.'}]
---
## Reason
Document the current deployment-reality architecture, core components, approval model, superseded design, and the earlier restart-point architecture as historical context.

## Raw Concept
**Task:**
Document the current Toolstack architecture pivot and the canonical build plan, while preserving the earlier greenfield restart-point architecture as the historical baseline.

**Changes:**
- Collapsed the earlier 9-service decomposition into deployment reality
- Defined Broker, Toolyard, Tool template, and Approval adapter as the four buildable things
- Declared nod the reference approval surface and Tailscale Serve the only ingress
- Marked component-plans.md and component-io-contracts.md as deleted and folded into plan.md
- Preserved the earlier restart-point architecture that centered on PROJECT.md, explicit ownership boundaries, transport-neutral contracts, and incremental component delivery

**Files:**
- plan.md
- PROJECT.md
- docs/component-decomposition.md
- docs/component-io-contracts.md
- docs/message-contracts.md
- docs/coding-standards.md
- docs/work-log.md
- docs/approval-surface-adapter.md

**Flow:**
agent -> tailnet ingress -> broker decision -> approval if needed -> tool container execution

**Timestamp:** 2026-06-13

**Author:** project notes

## Narrative
### Structure
The architecture is organized around physical trust boundaries rather than a distributed service mesh. Broker modules keep the old ownership seams internally, while Toolyard handles workload secret resolution and nod handles human approval messaging.

The prior Toolstack restart-point architecture centered on PROJECT.md and supporting docs for decomposition, IO contracts, message contracts, coding standards, plans, and work history. It was intentionally transport-neutral and boundary-driven, with explicit ownership boundaries established before persistent storage or transport choices.

### Dependencies
Depends on nod as the self-hosted approval surface, Infisical or SOPS as the secret backend, and Tailscale Serve as the only ingress. The earlier architecture depended on transport-neutral contracts and explicit ownership boundaries before any choice of REST, queues, databases, sandboxing, mTLS, or deployment shape.

### Highlights
The broker owns approval truth, secrets never touch the control plane, and the registry is physically secret-unaware. The build plan is explicitly phased so each component becomes runnable in sequence.

The earlier implementation strategy was intentionally incremental: build one component at a time, keep code boring and explicit, keep public surfaces small, and use focused tests to verify behavior and boundaries. The next recommended component in that earlier plan was ClientProfileService.

### Rules
Fail closed everywhere. Secrets live with the workload. The broker holds no secret-backend credential and is never on the secret path. The broker forwards approved calls directly to the tool container. Approval describes the operation, not the command.

Build one component at a time. Prefer boring, explicit code over clever abstractions. Keep public surfaces small. Keep tests focused on behavior and boundaries. (The earlier design's service-specific secret rules are superseded — those services are now broker module seams. The durable form: the broker is never on the secret path, and the registry is secret-unaware, reading toolyard.yaml and ignoring the secrets block.)

### Examples
Phase 0 stands up tailnet ingress plus a localhost-bound broker exposing only GET /v1/health. Phase 2 adds Toolyard and real tools; Phase 3 wires nod approval.

There is no active implementation or test suite yet. The next step is Phase 0: tailnet ingress plus a localhost-bound broker that serves only GET /v1/health and fails closed. (The earlier plan's "start with ClientProfileService" is superseded.)

## Facts
- **architecture_direction**: The architecture was collapsed on 2026-06-13 from a 9-service logical decomposition to deployment reality with hard physical boundaries. [project]
- **core_components**: The current design has four buildable things: Broker, Toolyard, Tool template, and Approval adapter. [project]
- **broker_role**: The broker is one Python process with one SQLite file and is the only address the agent can reach. [project]
- **toolyard_role**: Toolyard is the execution boundary and resolves per-tool secrets at container start into tmpfs. [project]
- **request_path**: The broker forwards approved calls directly to the tool container on 127.0.0.1:port and toolyard is not a request proxy. [project]
- **approval_model**: nod is the external approval surface and the broker owns approval truth while nod is a messenger. [project]
- **ingress**: The external ingress is Tailscale Serve as the only ingress path. [project]
- **security_spine**: The security spine includes fail-closed behavior, secrets never on the control plane, registry secret-unaware physically, redact before any boundary, hashed tokens with immediate revocation, operation-based approval, and every decision audited. [project]
- **build_order**: The build order is Phase 0 boundary, Phase 1 broker core, Phase 2 real tools, Phase 3 approval via nod, and Phase 4 admin plus hardening. [project]
- **superseded_docs**: docs/component-plans.md and docs/component-io-contracts.md were deleted and folded into plan.md. [project]
- **project_type**: Toolstack is a greenfield agentic tool management project. [project]
- **source_of_truth**: The source of truth starts at PROJECT.md. [project]
- **current_status**: The all-in-one scaffold was removed. The repo is in pre-implementation planning state and ready for the first isolated component. [project]
- **next_step**: The next step is Phase 0 — tailnet ingress plus a localhost-bound broker that serves only GET /v1/health and fails closed. [project]
- **registry_secret_awareness**: The registry is secret-unaware — the broker reads tool/op/risk/port from toolyard.yaml and ignores the secrets block. [project]
- **secret_path**: The broker holds no secret-backend credential and is never on the secret path; only toolyard resolves workload secrets at container start. [project]
- **broker_modules**: The old per-service responsibilities are now module seams inside the one broker process (Gateway, Identity, Policy, Registry-read, Request lifecycle, Approval + nod adapter, Audit). [project]
- **superseded_services**: SUPERSEDED — the separate -Service processes (BrokerGateway, ClientProfileService, RequestService, PolicyService, ToolRegistryService, ApprovalService, ToolRuntimeService, SecretsManagementService, EventLoggingService) and the standalone Approval Surface Endpoint no longer exist. [history]

## Cross References
- architecture/toolstack/component_decomposition.md
- architecture/toolstack/boundary_contracts.md
- architecture/toolstack/coding_standards.md
- architecture/toolstack/approval_surface_adapter.md
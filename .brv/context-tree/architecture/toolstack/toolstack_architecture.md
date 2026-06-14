---
title: Toolstack Architecture
summary: Toolstack architecture pivot to deployment reality with broker internals, direct tool forwarding, secret-at-workload handling, and phased build order.
tags: []
related: [project_management/work_log/context.md, architecture/toolstack/component_decomposition.md, architecture/toolstack/boundary_contracts.md, architecture/toolstack/coding_standards.md]
keywords: []
createdAt: '2026-06-14T04:19:11.775Z'
updatedAt: '2026-06-14T04:19:11.775Z'
---
## Reason
Curate the architecture pivot, build order, and current working rules for the Toolstack rebuild

## Raw Concept
**Task:**
Document the current Toolstack rebuild direction, including the architecture pivot, working rules, and build phases.

**Changes:**
- Collapsed the earlier 9-service decomposition into broker module seams
- Adopted nod as the approval surface via an in-broker adapter
- Removed the external approver process and direct proxying through toolyard
- Deleted superseded component plans and I/O contracts in favor of plan.md

**Files:**
- PROJECT.md
- plan.md
- docs/component-decomposition.md
- docs/message-contracts.md
- docs/approval-surface-adapter.md
- docs/work-log.md

**Flow:**
Phase 0 boundary -> Phase 1 broker core vs stub tool -> Phase 2 toolyard + real tools + secrets-at-workload -> Phase 3 approval via nod -> Phase 4 admin + hardening

**Timestamp:** 2026-06-14T04:18:38.993Z

## Narrative
### Structure
The project is organized around a collapsed deployment reality with a broker, toolyard, tool template, and an in-broker nod adapter, while former services remain only as internal broker seams.

### Dependencies
Depends on tailnet ingress, localhost-only broker binding, and local docs that define build order, message contracts, and approval-surface behavior.

### Highlights
The current plan emphasizes one component at a time, fail-closed behavior, secrets living with the workload, and direct broker-to-tool execution.

### Rules
Build one component at a time. Fail closed. Secrets live with the workload. The broker holds no secret-backend credential and is never on the secret path. The registry is secret-unaware. The broker owns approval truth. The broker forwards approved calls directly to the tool container. Defer profiles, mTLS/component credentials, multiple approval surfaces, and sandboxed jobs until needed.

### Examples
Phase 0 proves the agent can reach the broker over the tunnel and nothing else can.

## Facts
- **architecture_pivot_date**: The architecture pivot was recorded on 2026-06-13. [project]
- **phase_0_boundary**: Phase 0 is tailnet ingress plus a broker that binds 127.0.0.1 and serves only GET /v1/health. [project]
- **broker_default_behavior**: The broker fails closed on everything else. [project]
- **broker_tool_path**: The broker forwards approved calls directly to the tool container. [project]
- **toolyard_secret_handling**: Toolyard handles secret resolution at container start. [project]
- **registry_secret_awareness**: The registry is secret-unaware and the broker reads toolyard.yaml while ignoring the secrets block. [project]
- **secrets_location**: Secrets live with the workload and the broker holds no secret-backend credential. [project]
- **approval_truth**: The broker owns approval truth; nod is a messenger. [project]
- **deleted_docs**: Docs/component-plans.md and docs/component-io-contracts.md were deleted and folded into plan.md. [project]
- **canonical_docs**: Canonical docs are plan.md, docs/component-decomposition.md, docs/message-contracts.md, docs/approval-surface-adapter.md, and PROJECT.md. [project]

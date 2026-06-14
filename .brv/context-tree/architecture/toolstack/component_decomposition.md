---
title: Component Decomposition
summary: Collapsed Toolstack architecture with agent->broker->tool request flow, toolyard-managed secrets, nod approvals, broker module seams, trust boundaries, outcomes, audit taxonomy, and redaction rules.
tags: []
related: []
keywords: []
createdAt: '2026-06-14T04:16:01.694Z'
updatedAt: '2026-06-14T04:16:01.694Z'
---
## Reason
Document the collapsed deployment-reality architecture and broker module seams.

## Raw Concept
**Task:**
Document the current Toolstack component decomposition and boundary contracts that supersede the old 9-service model.

**Changes:**
- Collapsed the architecture to deployment reality with a few processes and hard physical boundaries.
- Moved former service responsibilities into broker module seams with in-process calls and one SQLite file.
- Defined boundary wire contracts only for process or trust boundaries.
- Clarified that toolyard starts containers and injects per-tool secrets at container start into tmpfs.
- Established nod as the external approval surface and the broker as the approval truth owner.

**Files:**
- docs/component-decomposition.md
- docs/message-contracts.md
- plan.md
- PROJECT.md

**Flow:**
agent -> tailnet ingress -> broker -> tool container; toolyard starts containers and injects secrets; broker <-> nod for approval; toolyard -> secret backend; operator -> broker

**Timestamp:** 2026-06-14

**Patterns:**
- `^POST /v1/actions/<tool>\.<op>$` - Agent to broker action endpoint
- `^POST /mcp/<tool>$` - Agent to broker MCP endpoint

## Narrative
### Structure
The architecture is split into a physical picture and an in-broker module seam picture. The physical boundary is tailnet ingress -> broker -> tool containers, with toolyard handling container lifecycle and secret injection off the request path.

### Dependencies
Depends on tailnet/VPN ingress, SQLite, nod, Toolyard, and a secret backend such as Infisical or SOPS. The broker reads tool registry data from disk and ignores the secrets block.

### Highlights
The broker forwards approved calls directly to localhost tool containers, never touches the secret backend, and owns approval truth. The old separate approval surface endpoint and nine service processes are superseded by broker module seams.

### Rules
These are modules in one process, not services. They share one SQLite file and call each other in-process — no network and no inter-module auth. Only toolyard talks to the secret backend, and only for workload secrets resolved at container start. The broker holds no secret-backend credential and is never on the secret path. Redact arguments and results before audit or approval cards. Raw tokens are never logged; any fingerprint is non-reversible. Nothing sensitive goes in a nod title/summary; use notification.redact.

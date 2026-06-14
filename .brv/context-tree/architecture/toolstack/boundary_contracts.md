---
title: Boundary Contracts
summary: Boundary contracts for agent, broker, toolyard, tool containers, and nod, including standard outcomes, audit event families, secrets access rules, and redaction requirements.
tags: []
related: []
keywords: []
createdAt: '2026-06-14T04:16:01.697Z'
updatedAt: '2026-06-14T04:16:01.697Z'
---
## Reason
Document the wire contracts, outcomes, secrets rule, audit taxonomy, and redaction rules at process boundaries.

## Raw Concept
**Task:**
Document boundary contracts that cross process or trust boundaries in the collapsed Toolstack architecture.

**Changes:**
- Defined standard outcomes: ok, accepted, pending_approval, denied, invalid, not_found, expired, unavailable, failed.
- Specified Agent->Broker, Broker->Tool container, Toolyard->Secret backend, Tool container->Toolyard, and Broker<->nod boundary messages.
- Captured audit event taxonomy families and redaction requirements.
- Stated that the approval boundary has its own spec in approval-surface-adapter.md.

**Files:**
- docs/message-contracts.md
- docs/approval-surface-adapter.md
- plan.md

**Flow:**
agent request -> broker policy/approval -> tool execution or denial -> audit/redaction -> optional approval boundary -> callback/poll

**Timestamp:** 2026-06-14

**Patterns:**
- `^Authorization: Bearer <token>$` - Bearer token auth header for agent to broker
- `^POST /v1/actions/<tool>\.<op>$` - REST action boundary
- `^POST /mcp/<tool>$` - JSON-RPC MCP boundary

## Narrative
### Structure
The document enumerates five boundaries, then standard outcomes, then audit taxonomy and redaction rules. Most former inter-service messages are now in-process broker calls and therefore have no wire contract.

### Dependencies
Depends on the collapsed architecture, the approval-surface adapter spec, and the broker audit module. Toolyard is the only component that talks to the secret backend.

### Highlights
Agent ingress is restricted to the broker, approved calls are forwarded to localhost tool containers, and secrets are injected at container start into tmpfs. Audit families cover gateway, identity, policy, request, approval, runtime, and admin events.

### Rules
Only GET /v1/health is open. Arguments are redacted before audit. The broker never inspects or materializes secrets. MCP frames are forwarded unchanged after the policy check on params.name. The broker owns approval truth; nod is the messenger. Raw tokens are never logged; any fingerprint is non-reversible. Nothing sensitive goes in a nod title/summary; use notification.redact.

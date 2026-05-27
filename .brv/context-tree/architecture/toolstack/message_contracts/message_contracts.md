---
title: Message Contracts
summary: Message contracts define the common envelope, standard outcomes, secrets-access rules, and the approved request/approval/runtime/admin messages.
tags: []
related: [architecture/toolstack/component_io_contracts.md, architecture/toolstack/component_design.md, architecture/toolstack/component_io_contracts/component_i_o_contracts.md]
keywords: []
createdAt: '2026-05-27T16:36:15.538Z'
updatedAt: '2026-05-27T16:52:46.213Z'
---
## Reason
Capture the transport-neutral message and outcome rules

## Raw Concept
**Task:**
Document the transport-neutral message contracts for the toolstack

**Changes:**
- Defined common envelope fields
- Enumerated standard outcomes and major message families
- Captured secrets access rules and admin contracts
- Defined the common envelope and standard outcomes
- Cataloged external client, orchestration, approval, runtime, secrets, admin, and event logging messages

**Files:**
- docs/message-contracts.md
- docs/component-io-contracts.md
- docs/component-decomposition.md

**Flow:**
sender -> standardized envelope -> receiver -> audit events -> outcome

**Timestamp:** 2026-05-27T16:51:34.761Z

## Narrative
### Structure
The message contract document is organized around shared principles, common envelopes, standard outcomes, secret-access rules, and specific logical message types.

### Dependencies
It depends on the component decomposition and I/O contracts to define allowed senders, receivers, and trust boundaries.

### Highlights
The document preserves exact security rules such as keeping secret values out of request, approval, registry, policy, and audit payloads except as redacted metadata.

### Rules
Messages describe expectations between components, not wire format. BrokerGateway only talks to ClientProfileService and RequestService. BrokerGateway has no direct path to SecretsManagementService. ToolRegistryService has no secret awareness. Approval surfaces are external and communicate through the Approval Surface Endpoint, not directly with request or policy state. RequestService owns mutable request state. EventLoggingService owns append-only audit/event history. Secret values must not appear in request, approval, registry, policy, or audit payloads except as redacted metadata. Every message should carry message_id, correlation_id, source_component, target_component, and issued_at unless the call is purely local and equivalent information is already available.

### Examples
ClientActionRequest includes client_id, profile_token, tool_id, operation, arguments, optional reason, and optional idempotency_key. AuthenticateProfileToken converts a profile token into authenticated client/profile context. SubmitRequest carries authenticated request context without raw profile tokens. MaterializeWorkloadSecrets requests prepared secret material for a specific execution context. AppendAuditEvent records redacted events for event logging.

## Facts
- **common_envelope**: Every message should carry message_id, correlation_id, source_component, target_component, and issued_at unless the call is purely local and equivalent context already exists. [convention]
- **standard_outcomes**: The standard outcomes include ok, accepted, pending_approval, denied, invalid, not_found, expired, unavailable, and failed. [convention]
- **direct_secret_restriction**: BrokerGateway, RequestService, and ToolRegistryService do not directly request or receive secrets. [convention]
- **approval_mediation**: Approval Surface Endpoint mediates approval prompts and decisions between ApprovalService and external approval surfaces. [project]

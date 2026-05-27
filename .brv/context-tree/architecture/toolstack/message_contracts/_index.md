---
children_hash: f5cf8e8bbd8b4289538506a049aa383ff6c2f9aaf88eef366e4436f25d70918b
compression_ratio: 0.6346578366445916
condensation_order: 0
covers: [message_contracts.md]
covers_token_total: 906
summary_level: d0
token_count: 575
type: summary
---
# d0 Structural Summary

## Message Contracts
`message_contracts.md` defines the transport-neutral contract layer for the toolstack: a shared envelope, standard outcomes, secret-access restrictions, and the approved message families used across request, approval, runtime, admin, secrets, and event logging flows.

### Core structure
- The contract is organized around:
  - shared principles
  - common envelope fields
  - standard outcomes
  - secret-access rules
  - specific logical message types
- Every message should carry `message_id`, `correlation_id`, `source_component`, `target_component`, and `issued_at` unless the call is purely local and equivalent context already exists.
- Messages describe expectations between components, not wire format.

### Security and trust boundaries
- Secret values must not appear in request, approval, registry, policy, or audit payloads except as redacted metadata.
- `BrokerGateway` only talks to `ClientProfileService` and `RequestService`.
- `BrokerGateway` has no direct path to `SecretsManagementService`.
- `ToolRegistryService` has no secret awareness.
- Approval surfaces are external and communicate through the `Approval Surface Endpoint`, not directly with request or policy state.
- `RequestService` owns mutable request state.
- `EventLoggingService` owns append-only audit/event history.

### Standard outcomes
- The canonical outcomes are: `ok`, `accepted`, `pending_approval`, `denied`, `invalid`, `not_found`, `expired`, `unavailable`, and `failed`.

### Major message families
- External client messages
- Orchestration messages
- Approval messages
- Runtime messages
- Secrets messages
- Admin messages
- Event logging messages

### Drill-down references
- See `component_io_contracts.md` for I/O constraints and interface boundaries.
- See `component_design.md` and `component_decomposition.md` for component roles and trust relationships.

### Key examples captured
- `ClientActionRequest`
- `AuthenticateProfileToken`
- `SubmitRequest`
- `MaterializeWorkloadSecrets`
- `AppendAuditEvent`

### Key facts
- `BrokerGateway`, `RequestService`, and `ToolRegistryService` do not directly request or receive secrets.
- `Approval Surface Endpoint` mediates approval prompts and decisions between `ApprovalService` and external approval surfaces.
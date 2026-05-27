---
children_hash: 65c8cce1b3f50af52625aa9acf7d423e8d823d3d60c45e11f18b8654e505ff7b
compression_ratio: 0.8920454545454546
condensation_order: 0
covers: [component_decomposition.md]
covers_token_total: 528
summary_level: d0
token_count: 471
type: summary
---
# d0 Structural Summary

## Component Decomposition
The toolstack is organized as a set of isolated services with explicit trust boundaries and narrow allowed interactions. The core flow is:

**external client zone → gateway → request orchestration → approval / runtime / secrets / event logging zones**

### Main Components
- **BrokerGateway**: entry point for the client side
- **ClientProfileService**: supports gateway interactions
- **RequestService**: owns mutable request lifecycle state
- **PolicyService**: governs request decisions
- **ToolRegistryService**: registry layer with no secret awareness
- **ApprovalService** and **Approval Surface Endpoint**: handle approval flows
- **ToolRuntimeService**: executes runtime actions
- **SecretsManagementService**: owns secret namespaces and component-to-component credentials
- **EventLoggingService**: owns append-only audit/event history
- **Control Panel**: operational interface for the system

### Architectural Rules and Relationships
- The design enforces **trust-zone separation** so secrets, approvals, runtime, and event logging remain independent.
- **BrokerGateway** only communicates with **ClientProfileService** and **RequestService**.
- **BrokerGateway**, **RequestService**, and **ToolRegistryService** have **no direct secret path**.
- The system is intentionally **explicit and “boring”**, favoring clear ownership over hidden coupling.

### Key Ownership Facts
- **RequestService** owns request lifecycle state.
- **EventLoggingService** owns append-only audit/event history.
- **ToolRegistryService** has no secret awareness.
- **SecretsManagementService** owns secret namespaces and component credentials.

### Drill-Down References
- See **component_io_contracts.md** for service I/O constraints and allowed interactions.
- See **message_contracts.md** for message-level contract definitions and boundaries.
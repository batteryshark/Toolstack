---
children_hash: 180d956b65be261a0e3e81a41de95de7ff1335c35b81dc6ea249eeec5f7b61ca
compression_ratio: 0.743006993006993
condensation_order: 0
covers: [component_decomposition.md]
covers_token_total: 572
summary_level: d0
token_count: 425
type: summary
---
## Component Decomposition Overview

The component decomposition establishes a threat-model-oriented trust-zone layout for the toolstack, separating **External Agent/Client**, **Admin Operator**, **Core Control Plane**, **External Approval Surface**, **Tool Runtime**, **Secrets**, and **Event Logging**. The primary flow is **external agent/client -> gateway -> request orchestration -> approval/runtime/secrets/event logging**, with explicit ownership and boundary rules.

### Core boundaries and routing
- **BrokerGateway** is the only normal entry point for agent/client action requests.
- It is limited to **ClientProfileService** and **RequestService**.
- **Approval Surface Endpoint** is a separate external boundary, not part of the normal gateway path.

### Control-plane orchestration
- **RequestService** coordinates with:
  - **PolicyService**
  - **ToolRegistryService**
  - **ApprovalService**
  - **ToolRuntimeService**
- This makes the **Core Control Plane** the central orchestration zone for request handling and policy enforcement.

### Secrets and runtime ownership
- **SecretsManagementService** owns:
  - workload secrets
  - component-to-component credentials
- **ToolRuntimeService** requests secrets using the active profile/tool execution context.
- **ToolRegistryService** has **no secret awareness** and must not declare:
  - secret namespaces
  - secret keys
  - secret requirements

### Event logging
- **EventLoggingService** receives redacted events from every domain.
- It is **append-only** and does **not** own mutable request state.

### Drill-down entry
- See **component_decomposition.md** for the full diagram, trust-zone details, and ownership rules.

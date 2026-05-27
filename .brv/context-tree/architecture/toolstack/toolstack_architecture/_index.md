---
children_hash: 885308d9658d3704b7a3abd69ff1cdebc9a4e4a72ecb7a391a16c761525f53c9
compression_ratio: 0.7058823529411765
condensation_order: 0
covers: [toolstack_architecture.md]
covers_token_total: 731
summary_level: d0
token_count: 516
type: summary
---
# Toolstack Architecture Overview

The Toolstack rebuild is at a deliberate restart point: the earlier all-in-one scaffold was removed, and the repository was reset to a pre-implementation planning state. There is no active source implementation or test suite yet; the architecture is being defined first, then components will be built one at a time.

## Core architectural direction
- The rebuild is **transport-neutral** and intentionally postpones decisions about REST, queues, databases, sandboxing, mTLS, and deployment shape until a specific component requires them.
- The system is being simplified into **isolated components** with explicit ownership boundaries and small public surfaces.
- The guiding build rule is: **one component at a time**, with focused tests that verify behavior and boundaries.

## Documentation structure and role
- **Toolstack Architecture** establishes the restart point and the main rules for the rebuild.
- **PROJECT.md** is the central hub, linking to architecture, coding standards, component plans, and the work log.
- Supporting docs referenced for drill-down:
  - `architecture/toolstack/coding_standards/coding_standards.md`
  - `architecture/toolstack/component_design/component_decomposition.md`
  - `architecture/toolstack/component_io_contracts/component_i_o_contracts.md`
  - `architecture/toolstack/message_contracts/message_contracts.md`

## Explicit rules and constraints
- Prefer boring, explicit code over clever abstractions.
- Keep public surfaces small.
- Keep tests focused on behavior and boundaries.
- Do not let `BrokerGateway`, `RequestService`, or `ToolRegistryService` talk directly to `SecretsManagementService`.
- Do not let `ToolRegistryService` know secret namespaces, secret keys, or secret requirements.

## Current status and next step
- The repo is in a **pre-implementation state** and the restart point is `PROJECT.md`.
- The next recommended component is **ClientProfileService**.
- `.brv/config.json` was adjusted to be path-agnostic by changing `cwd` from an absolute local path to `.`.
# Toolstack Rebuild

Greenfield component decomposition for an agentic tool management system.

Start with [PROJECT.md](PROJECT.md). It is the project nerve center and restart
point.

This repository intentionally starts with logical boundaries and planning docs.
It does not choose REST routes, database schemas, sandboxing, mTLS, or
deployment topology yet.

## Core Components

- `BrokerGateway` accepts client requests and delegates request lifecycle work.
- `ClientProfileService` owns clients, profiles, profile tokens, and grants.
- `RequestService` owns mutable request state.
- `PolicyService` owns tool authorization and temporary grants.
- `ApprovalService` owns approval workflow state and outcomes.
- `ToolRegistryService` owns tool catalog metadata and has no secret awareness.
- `ToolRuntimeService` owns tool execution and runtime preparation.
- `SecretsManagementService` owns secret namespaces and profile/tool bindings.
- `ToolMonitoringService` owns append-only audit events.

## Implementation Status

No active component implementation exists yet. The next step is to build the
first component in isolation, starting with `ClientProfileService`.

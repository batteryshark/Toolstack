# Component I/O Contracts

This document describes each component at a higher level than individual
messages. It answers:

- what the component owns;
- what it consumes;
- what it produces;
- what it must not know or do.

These are logical contracts, not deployment or transport choices.

## Summary Table

| Component | Consumes | Produces |
|---|---|---|
| `BrokerGateway` | External client request, profile token validation result | Authenticated request context, client-facing response |
| `ClientProfileService` | Profile tokens, admin client/profile changes, component auth material | Client/profile context, token status, profile records |
| `RequestService` | Authenticated request context, policy decisions, tool metadata, approval outcomes, runtime results | Request state, orchestration commands, lifecycle events |
| `PolicyService` | Profile id, tool id, operation, risk hint, policy/grant state | Allow/deny/approval-required decisions, grant state changes |
| `ToolRegistryService` | Tool catalog admin changes, tool metadata source | Tool definitions, operation metadata, risk hints, runtime requirements |
| `ApprovalService` | Approval-required requests, external approval outcomes, approval config | Approval prompts, approval state, normalized outcomes |
| `Approval Surface Endpoint` | Approval prompts, external surface decisions | Surface deliveries, normalized decision submissions |
| `ToolRuntimeService` | Execution requests, tool definitions, secret materialization responses, tool results | Prepared invocations, runtime status, execution results |
| `SecretsManagementService` | Namespace bindings, component credential requests, backend secret data | Workload secret materialization, component credentials, secret metadata |
| `EventLoggingService` | Redacted events from components | Append-only audit history, query results, exports |
| `Control Panel` | Admin input, domain service summaries, audit views | Admin change requests, management views |

## Component Contracts

### `BrokerGateway`

Owns:

- external request ingress;
- client-facing response shape;
- correlation id creation or propagation.

Consumes:

- client id and profile token from the external client zone;
- token validation result from `ClientProfileService`;
- request result from `RequestService`.

Produces:

- authenticated request context for `RequestService`;
- client-facing result, denial, pending-approval status, or failure response;
- ingress/egress audit events.

Must not:

- call `SecretsManagementService`;
- call `PolicyService`, `ToolRegistryService`, `ApprovalService`, or `ToolRuntimeService` directly;
- materialize or inspect secrets;
- own request lifecycle state.

### `ClientProfileService`

Owns:

- clients;
- profiles;
- profile tokens;
- client-to-profile grants and status.

Consumes:

- profile token validation requests from `BrokerGateway`;
- admin changes from `Control Panel`;
- component auth material from `SecretsManagementService` when needed for its own internals.

Produces:

- authenticated client/profile context;
- token validity, expiry, and revocation status;
- client/profile management summaries;
- profile-related audit events.

Must not:

- decide tool authorization;
- bind tools to secret namespaces;
- execute tools;
- expose raw tokens in logs or audit payloads.

### `RequestService`

Owns:

- mutable request lifecycle state;
- request status transitions;
- orchestration across policy, approval, registry, runtime, and event logging.

Consumes:

- authenticated request context from `BrokerGateway`;
- tool metadata from `ToolRegistryService`;
- policy decisions from `PolicyService`;
- approval outcomes from `ApprovalService`;
- execution results from `ToolRuntimeService`.

Produces:

- request records and status changes;
- policy evaluation requests;
- approval workflow requests;
- tool execution requests;
- request lifecycle audit events.

Must not:

- call `SecretsManagementService`;
- authenticate raw profile tokens;
- decide policy internally;
- inspect tool secret needs;
- own append-only audit storage.

### `PolicyService`

Owns:

- policy definitions;
- profile-policy bindings;
- profile-to-tool operation authorization;
- policy overrides;
- temporary grants and just-in-time elevations.

Consumes:

- profile id, tool id, operation, and risk hint from `RequestService`;
- policy/grant admin changes from `Control Panel`;
- component auth material from `SecretsManagementService` when needed for policy backends.

Produces:

- allow, deny, or approval-required decisions;
- policy reasons and risk treatment;
- grant state changes;
- policy decision audit events.

Must not:

- materialize workload secrets;
- execute tools;
- manage approval surface delivery;
- mutate request lifecycle state.

### `ToolRegistryService`

Owns:

- tool catalog;
- tool identity;
- operation names;
- operation descriptions;
- risk hints;
- runtime requirements.

Consumes:

- tool catalog admin changes from `Control Panel`;
- tool metadata source data.

Produces:

- tool definitions;
- operation metadata;
- risk hints;
- runtime requirements;
- catalog change audit events.

Must not:

- declare secret namespaces;
- declare secret keys;
- declare secret requirements;
- know profile/tool namespace bindings;
- execute tools.

### `ApprovalService`

Owns:

- approval workflow state;
- pending approvals;
- approval timeouts;
- normalized approval outcomes;
- approval surface configuration.

Consumes:

- approval-required requests from `RequestService`;
- normalized decisions from `Approval Surface Endpoint`;
- approval configuration changes from `Control Panel`;
- component auth material from `SecretsManagementService` for external approval integrations.

Produces:

- approval prompts;
- approval state transitions;
- approved, rejected, expired, or escalated outcomes;
- approval audit events.

Must not:

- decide initial tool authorization;
- execute tools;
- directly trust external surface identity without endpoint validation;
- include raw secrets in prompts.

### `Approval Surface Endpoint`

Owns:

- boundary between core approval workflow and external approval surfaces;
- surface-specific delivery and inbound decision normalization.

Consumes:

- approval prompts from `ApprovalService`;
- decisions, comments, and escalation requests from external messaging apps or agent runtimes.

Produces:

- surface delivery results;
- normalized approval decisions for `ApprovalService`;
- surface delivery and decision audit events.

Must not:

- own approval truth;
- mutate request state directly;
- bypass `ApprovalService`;
- treat external surface identifiers as authority without validation.

### `ToolRuntimeService`

Owns:

- tool instances;
- runtime backend selection;
- runtime lifecycle;
- execution preparation;
- health and status.

Consumes:

- execution requests from `RequestService`;
- tool definitions from `ToolRegistryService` through the request context;
- workload secret materialization from `SecretsManagementService`;
- tool execution results from tool instances;
- runtime admin changes from `Control Panel`.

Produces:

- prepared tool invocations;
- runtime status;
- execution results;
- runtime and execution audit events.

Must not:

- decide whether a profile is authorized to call a tool;
- know registry-level secret manifests;
- expose raw secret material in runtime metadata, audit, or approval payloads.

### `SecretsManagementService`

Owns:

- secret namespaces;
- profile/tool-to-namespace bindings;
- workload secret materialization;
- component-to-component credentials;
- backend mappings;
- writeback rules.

Consumes:

- namespace and credential admin changes from `Control Panel`;
- workload materialization requests from `ToolRuntimeService`;
- component credential requests from allowed internal components;
- secret data from configured backends.

Produces:

- prepared workload secret material for runtime;
- component credentials or credential references;
- namespace and credential metadata;
- secret materialization and credential audit events.

Must not:

- receive direct requests from `BrokerGateway`;
- receive direct requests from `RequestService`;
- receive direct requests from `ToolRegistryService`;
- expose secret values in audit payloads.

### `EventLoggingService`

Owns:

- append-only audit/event history;
- audit query surface;
- retention/export coordination.

Consumes:

- redacted events from domain components;
- audit queries from `Control Panel`;
- component credentials from `SecretsManagementService` when needed for audit stores or export sinks.

Produces:

- immutable audit records;
- filtered audit views;
- audit export streams;
- event logging health/status.

Must not:

- own mutable request lifecycle state;
- become a side channel for raw secrets;
- make authorization decisions.

### `Control Panel`

Owns:

- administrative user experience;
- management workflows;
- composed views over domain service state.

Consumes:

- admin input;
- domain service summaries;
- audit query results.

Produces:

- admin change requests to owning services;
- management views;
- admin audit events.

Must not:

- own primary domain state;
- bypass domain service authorization;
- write directly to backend stores as a substitute for service contracts.

## Zone-Level Contracts

### External Agent / Client Zone

Consumes client-facing responses from `BrokerGateway` and produces action
requests with client/profile credentials. It never receives workload secrets.

### Core Control Plane Trust Zone

Owns request coordination, profile identity, policy, registry, and approval
truth. It should stay free of workload secret values except where a component
has an explicit component-credential need.

### External Approval Surface Zone

Consumes approval prompts and produces approval decisions. It is outside core
trust and should only receive redacted, human- or agent-readable summaries.

### Tool Runtime Trust Zone

Consumes approved execution requests and prepared secret material. It produces
tool results and runtime status.

### Secrets Trust Zone

Consumes namespace/credential requests and backend secret data. It produces
secret material or credential references only for allowed components.

### Event Logging / Audit Trust Zone

Consumes redacted events and produces append-only history. It is not a control
plane for changing request, policy, approval, runtime, or secret state.

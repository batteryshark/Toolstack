# Component Plans

These are high-level build plans. Each component should still get a focused
implementation plan before major code is added.

## 1. `ClientProfileService`

Goal: authenticate clients and profiles without knowing tools, policies, or
secrets.

Build:

- client records;
- profile records;
- profile token issuance and validation;
- client-to-profile grants;
- revocation and expiry behavior;
- focused tests for valid, invalid, expired, and revoked tokens.

Do not build:

- tool authorization;
- secret namespace bindings;
- admin UI;
- transport.

## 2. `ToolMonitoringService`

Goal: provide append-only audit events that every other component can depend on.

Build:

- audit event model;
- redaction helper;
- append-only in-memory store;
- query by request id, component, event type, and correlation id;
- tests proving redaction and immutability expectations.

Do not build:

- log export;
- retention policy;
- external observability integrations.

## 3. `ToolRegistryService`

Goal: catalog tools and operations without secret awareness.

Build:

- tool definition model;
- operation metadata;
- risk hints;
- runtime requirements;
- catalog add/update/read behavior;
- tests proving no secret namespace/key fields are part of registry contracts.

Do not build:

- secret manifests;
- runtime lifecycle;
- policy decisions.

## 4. `PolicyService`

Goal: decide whether a profile may call a tool operation.

Build:

- policy records;
- profile-policy bindings;
- allow, deny, approval-required decisions;
- temporary grants;
- tests for missing policy, denied operation, allowed operation, approval-required operation, and grant use.

Do not build:

- approval workflow state;
- secret access decisions;
- request lifecycle state.

## 5. `RequestService`

Goal: coordinate request lifecycle without owning every domain.

Build:

- request state model;
- state transitions;
- orchestration across registry, policy, approval, runtime, and monitoring;
- tests for denied, approved, pending, rejected, failed, and completed requests.

Do not build:

- profile token authentication;
- secret materialization;
- runtime internals.

## 6. `ApprovalService`

Goal: manage approval workflow state and normalized outcomes.

Build:

- approval request model;
- approval state transitions;
- timeout/expiry behavior;
- endpoint-facing prompt payloads;
- normalized approve/reject/escalate outcomes.

Do not build:

- Discord, Matrix, ntfy, or mobile-specific clients;
- policy decisions;
- tool execution.

## 7. `SecretsManagementService`

Goal: manage workload namespaces and component-to-component credentials.

Build:

- namespace records;
- profile/tool namespace bindings;
- workload materialization contract;
- component credential request contract;
- writeback permission model;
- tests proving `BrokerGateway`, `RequestService`, and `ToolRegistryService` are not allowed direct secret consumers.

Do not build:

- a specific external secret backend first;
- registry secret manifests.

## 8. `ToolRuntimeService`

Goal: prepare and execute tool invocations after request authorization.

Build:

- runtime instance model;
- handler/backend interface;
- execution preparation;
- secret materialization call into `SecretsManagementService`;
- result normalization;
- tests for missing runtime, missing expected tool secret, tool failure, and success.

Do not build:

- policy decisions;
- profile authentication;
- tool catalog ownership.

## 9. `BrokerGateway`

Goal: keep the external action ingress thin and boring.

Build:

- client-facing request adapter;
- profile token validation call;
- request submission call;
- response normalization.

Do not build:

- direct policy calls;
- direct runtime calls;
- direct secret calls.

## 10. `Control Panel`

Goal: provide admin workflows over domain services without owning primary state.

Build later, after the domain services are stable.

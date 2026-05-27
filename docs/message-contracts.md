# Message Contracts

This document defines logical message contracts between components and trust
zones. It is transport-neutral: these contracts may later become in-process
calls, REST resources, RPC methods, queue messages, or another mechanism.

The component diagram in [component-decomposition.md](component-decomposition.md)
is the source of truth for allowed relationships. For higher-level component
consume/produce boundaries, see
[component-io-contracts.md](component-io-contracts.md).

## Contract Principles

- Messages describe expectations between components, not wire format.
- `BrokerGateway` only talks to `ClientProfileService` and `RequestService`.
- `BrokerGateway` has no direct path to `SecretsManagementService`.
- `ToolRegistryService` has no secret awareness. It never declares secret
  namespaces, secret keys, or secret requirements.
- Approval surfaces are external. They communicate through the `Approval Surface
  Endpoint`, not directly with request or policy state.
- `RequestService` owns mutable request state.
- `EventLoggingService` owns append-only audit/event history.
- Secret values must not appear in request, approval, registry, policy, or audit
  payloads except as redacted metadata.

## Common Envelope

Every message should carry this minimal envelope unless the call is purely local
and the same information is already available in process context.

| Field | Required | Meaning |
|---|---:|---|
| `message_id` | yes | Unique id for this message. |
| `correlation_id` | yes | Stable id tying together one external request or admin workflow. |
| `source_component` | yes | Component sending the message. |
| `target_component` | yes | Component expected to handle the message. |
| `issued_at` | yes | Time the message was created. |
| `actor_context` | no | Client id, profile id, admin id, approver id, or service actor. |
| `audit_hints` | no | Redaction and classification hints for downstream audit. |

## Standard Outcomes

| Outcome | Meaning |
|---|---|
| `ok` | Request completed successfully. |
| `accepted` | Request was accepted for later processing. |
| `pending_approval` | Request is paused until approval resolves. |
| `denied` | Policy, profile, secret, or approval rules refused the request. |
| `invalid` | Message was malformed or semantically invalid. |
| `not_found` | Referenced component-owned resource does not exist. |
| `expired` | Request, approval, token, or grant expired. |
| `unavailable` | Target component, backend, or external surface is unavailable. |
| `failed` | Target attempted the work and failed. |

## Secrets Access Rules

Only these components may have direct contracts with `SecretsManagementService`:

| Component | Allowed secret interaction |
|---|---|
| `ClientProfileService` | Component credentials for token signing, verification, or profile-auth internals. |
| `PolicyService` | Component credentials for policy backends or grant stores. |
| `ApprovalService` | Component credentials for approval surfaces, signing, or approver integrations. |
| `ToolRuntimeService` | Workload secret materialization for profile/tool execution contexts. |
| `EventLoggingService` | Component credentials for audit storage, export, or event log sinks. |
| `Control Panel` | Admin management of namespaces and component credentials through normal admin authorization. |

`BrokerGateway`, `RequestService`, and `ToolRegistryService` do not directly
request or receive secrets.

## External Client Flow

### `ClientActionRequest`

| Item | Contract |
|---|---|
| Sender | Agent or client runtime |
| Receiver | `BrokerGateway` |
| Purpose | Ask the system to perform one tool operation under a profile. |
| Request fields | `client_id`, `profile_token`, `tool_id`, `operation`, `arguments`, optional `reason`, optional `idempotency_key` |
| Response fields | `request_id`, `status`, optional `result`, optional `approval_id`, optional `error`, optional `comments` |
| Outcomes | `ok`, `pending_approval`, `denied`, `invalid`, `not_found`, `unavailable`, `failed` |
| Audit events | `gateway.request_received`, `gateway.response_returned` |
| Security notes | Arguments may contain sensitive-looking data and must be redacted before audit. The gateway does not inspect, request, or materialize secrets. |

### `AuthenticateProfileToken`

| Item | Contract |
|---|---|
| Sender | `BrokerGateway` |
| Receiver | `ClientProfileService` |
| Purpose | Convert a profile token into authenticated client/profile context. |
| Request fields | `profile_token`, optional `client_id_hint` |
| Response fields | `client_id`, `profile_id`, `client_status`, `profile_status`, optional `token_expires_at` |
| Outcomes | `ok`, `denied`, `invalid`, `expired`, `not_found`, `unavailable` |
| Audit events | `profile.token_validated`, `profile.token_rejected` |
| Security notes | Raw tokens must not be logged. Any token fingerprint in audit must be non-reversible. |

### `SubmitRequest`

| Item | Contract |
|---|---|
| Sender | `BrokerGateway` |
| Receiver | `RequestService` |
| Purpose | Submit an authenticated request context for lifecycle handling. |
| Request fields | `client_id`, `profile_id`, `tool_id`, `operation`, `arguments`, optional `reason`, `correlation_id` |
| Response fields | `request_id`, `status`, optional `result`, optional `approval_id`, optional `error` |
| Outcomes | `ok`, `accepted`, `pending_approval`, `denied`, `invalid`, `not_found`, `failed` |
| Audit events | `request.received`, `request.completed`, `request.denied`, `request.failed` |
| Security notes | This message is already authenticated. It must not include raw profile tokens. |

## Request Orchestration

### `LookupToolOperation`

| Item | Contract |
|---|---|
| Sender | `RequestService` |
| Receiver | `ToolRegistryService` |
| Purpose | Resolve tool metadata and operation risk hints. |
| Request fields | `tool_id`, `operation` |
| Response fields | `tool_id`, `operation`, `description`, `risk_hint`, `runtime_requirements` |
| Outcomes | `ok`, `not_found`, `invalid`, `unavailable` |
| Audit events | `registry.tool_lookup`, `registry.tool_lookup_failed` |
| Security notes | Response must not contain secret namespaces, secret keys, secret paths, or credential requirements. |

### `EvaluatePolicy`

| Item | Contract |
|---|---|
| Sender | `RequestService` |
| Receiver | `PolicyService` |
| Purpose | Decide whether a profile may call a tool operation. |
| Request fields | `request_id`, `client_id`, `profile_id`, `tool_id`, `operation`, `risk_hint`, optional `reason`, optional redacted argument summary |
| Response fields | `effect`, `reason`, `risk_treatment`, optional `grant_id`, optional `approval_policy` |
| Outcomes | `ok`, `denied`, `invalid`, `unavailable`, `failed` |
| Audit events | `policy.decision_allow`, `policy.decision_deny`, `policy.decision_approval_required` |
| Security notes | Policy decides tool authority, not secret namespace availability. |

### `OpenApproval`

| Item | Contract |
|---|---|
| Sender | `RequestService` |
| Receiver | `ApprovalService` |
| Purpose | Create an approval workflow for a request that policy marked as approval-required. |
| Request fields | `request_id`, `client_id`, `profile_id`, `tool_id`, `operation`, `risk_treatment`, `policy_reason`, optional `reason`, redacted `argument_summary` |
| Response fields | `approval_id`, `status`, optional `expires_at`, optional `surface_targets` |
| Outcomes | `accepted`, `pending_approval`, `invalid`, `unavailable`, `failed` |
| Audit events | `approval.opened` |
| Security notes | Approval prompts describe the operation and impact. They must not contain raw secrets. |

### `ExecuteTool`

| Item | Contract |
|---|---|
| Sender | `RequestService` |
| Receiver | `ToolRuntimeService` |
| Purpose | Execute an allowed or approved tool operation. |
| Request fields | `request_id`, `client_id`, `profile_id`, `tool_id`, `operation`, `arguments`, optional `reason`, `runtime_requirements` |
| Response fields | `status`, optional `result`, optional `error`, optional `runtime_metadata` |
| Outcomes | `ok`, `accepted`, `invalid`, `not_found`, `unavailable`, `failed` |
| Audit events | `runtime.execution_started`, `runtime.execution_completed`, `runtime.execution_failed` |
| Security notes | `RequestService` does not attach secrets. Runtime is responsible for asking `SecretsManagementService` for the profile/tool execution context. |

## Approval Boundary

### `PublishApprovalPrompt`

| Item | Contract |
|---|---|
| Sender | `ApprovalService` |
| Receiver | `Approval Surface Endpoint` |
| Purpose | Ask the endpoint boundary to publish or update an approval prompt. |
| Request fields | `approval_id`, `request_id`, `prompt_summary`, `risk_treatment`, `expires_at`, `allowed_actions` |
| Response fields | `surface_message_id`, `delivery_status`, optional `error` |
| Outcomes | `ok`, `accepted`, `invalid`, `unavailable`, `failed` |
| Audit events | `approval.prompt_publish_requested`, `approval.prompt_published`, `approval.prompt_publish_failed` |
| Security notes | This crosses toward external systems. Prompt content must be pre-redacted and safe to show outside the core trust zone. |

### `DeliverApprovalPrompt`

| Item | Contract |
|---|---|
| Sender | `Approval Surface Endpoint` |
| Receiver | External messaging app, mobile surface, or approval-agent runtime |
| Purpose | Deliver a human- or agent-readable approval prompt. |
| Request fields | `surface_message_id`, `approval_id`, `prompt_summary`, `allowed_actions`, optional `expires_at` |
| Response fields | `delivery_status`, optional `external_message_ref`, optional `error` |
| Outcomes | `ok`, `accepted`, `invalid`, `unavailable`, `failed` |
| Audit events | `approval.surface_delivered`, `approval.surface_delivery_failed` |
| Security notes | External surfaces are outside the core trust zone. Avoid payloads that expose sensitive arguments or secret material. |

### `SubmitApprovalDecision`

| Item | Contract |
|---|---|
| Sender | External approval surface |
| Receiver | `Approval Surface Endpoint` |
| Purpose | Return an approve, reject, comment, or escalation decision. |
| Request fields | `approval_id`, `surface_message_id`, `decision`, `approver_ref`, optional `comment`, optional `decision_time` |
| Response fields | `decision_status`, optional `error` |
| Outcomes | `ok`, `denied`, `invalid`, `expired`, `not_found`, `unavailable`, `failed` |
| Audit events | `approval.surface_decision_received`, `approval.surface_decision_rejected` |
| Security notes | The endpoint validates the surface actor before forwarding the decision into core approval state. |

### `RecordApprovalOutcome`

| Item | Contract |
|---|---|
| Sender | `Approval Surface Endpoint` |
| Receiver | `ApprovalService` |
| Purpose | Record the normalized approval outcome in the approval workflow. |
| Request fields | `approval_id`, `decision`, `approver_id`, optional `comment`, optional `surface_ref` |
| Response fields | `approval_id`, `status`, `request_id`, optional `decision_note` |
| Outcomes | `ok`, `denied`, `invalid`, `expired`, `not_found`, `failed` |
| Audit events | `approval.approved`, `approval.rejected`, `approval.expired` |
| Security notes | ApprovalService owns approval truth. External surface identifiers are metadata, not authority by themselves. |

## Runtime And Secrets

### `MaterializeWorkloadSecrets`

| Item | Contract |
|---|---|
| Sender | `ToolRuntimeService` |
| Receiver | `SecretsManagementService` |
| Purpose | Prepare workload secret material for a specific profile/tool execution context. |
| Request fields | `request_id`, `profile_id`, `tool_id`, `runtime_context`, optional `writeback_requested` |
| Response fields | `materialization_id`, `namespace_ref`, `delivery_mode`, redacted `materialized_keys_summary`, `allow_writeback` |
| Outcomes | `ok`, `denied`, `invalid`, `not_found`, `unavailable`, `failed` |
| Audit events | `secrets.workload_materialized`, `secrets.workload_denied`, `secrets.workload_failed` |
| Security notes | The response may cause secret values to be delivered to runtime, but contract logs and audit payloads only contain redacted summaries. |

### `PreparedToolInvocation`

| Item | Contract |
|---|---|
| Sender | `ToolRuntimeService` |
| Receiver | Tool instance |
| Purpose | Invoke a tool with arguments and prepared runtime context. |
| Request fields | `request_id`, `tool_id`, `operation`, `arguments`, prepared execution context, secret material delivery selected by runtime |
| Response fields | `status`, optional `result`, optional `error`, optional `tool_metadata` |
| Outcomes | `ok`, `invalid`, `unavailable`, `failed` |
| Audit events | `tool.invocation_started`, `tool.invocation_completed`, `tool.invocation_failed` |
| Security notes | The tool implicitly knows which env vars, files, or keys it expects. Missing expected secrets are runtime/tool configuration failures. |

### `ToolExecutionResult`

| Item | Contract |
|---|---|
| Sender | Tool instance |
| Receiver | `ToolRuntimeService` |
| Purpose | Return tool output or failure details to runtime. |
| Request fields | `request_id`, `status`, optional `result`, optional `error`, optional `tool_metadata` |
| Response fields | `acknowledged`, optional `error` |
| Outcomes | `ok`, `invalid`, `failed` |
| Audit events | `tool.result_received` |
| Security notes | Tool output may contain sensitive data. Runtime applies redaction hints before audit or approval display. |

### `ComponentCredentialRequest`

| Item | Contract |
|---|---|
| Sender | `ClientProfileService`, `PolicyService`, `ApprovalService`, `ToolRuntimeService`, `EventLoggingService`, or admin `Control Panel` |
| Receiver | `SecretsManagementService` |
| Purpose | Request credentials used by components to authenticate to their own backends or peers. |
| Request fields | `component_id`, `credential_purpose`, optional `backend_ref`, optional `rotation_policy_ref` |
| Response fields | `credential_ref`, `delivery_mode`, optional `expires_at`, redacted `credential_summary` |
| Outcomes | `ok`, `denied`, `invalid`, `not_found`, `unavailable`, `failed` |
| Audit events | `secrets.component_credential_issued`, `secrets.component_credential_denied` |
| Security notes | `BrokerGateway`, `RequestService`, and `ToolRegistryService` are not allowed senders for this contract. |

### `ComponentCredentialRotation`

| Item | Contract |
|---|---|
| Sender | `SecretsManagementService` |
| Receiver | Credential consumer or backing secret store |
| Purpose | Rotate, revoke, or update a component credential. |
| Request fields | `credential_ref`, `component_id`, `rotation_reason`, optional `effective_at` |
| Response fields | `rotation_status`, optional `new_credential_ref`, optional `error` |
| Outcomes | `ok`, `accepted`, `denied`, `invalid`, `not_found`, `unavailable`, `failed` |
| Audit events | `secrets.component_credential_rotated`, `secrets.component_credential_rotation_failed` |
| Security notes | Rotation events must not expose raw credential values. |

## Admin And Control Plane

### Admin Message Contracts

| Message | Sender | Receiver | Purpose | Request fields | Response fields | Outcomes | Audit events | Security notes |
|---|---|---|---|---|---|---|---|---|
| `ManageClientProfile` | `Control Panel` | `ClientProfileService` | Create, update, revoke, or inspect clients, profiles, and profile tokens. | `admin_id`, `operation`, client/profile fields | changed resource summary, optional one-time token material | `ok`, `denied`, `invalid`, `not_found`, `failed` | `admin.client_profile_changed` | One-time secrets are shown only through the intended admin channel. |
| `ManagePolicy` | `Control Panel` | `PolicyService` | Manage policies, bindings, overrides, and grants. | `admin_id`, `operation`, policy/grant fields | changed policy/grant summary | `ok`, `denied`, `invalid`, `not_found`, `failed` | `admin.policy_changed` | Policy changes affect future requests and must be auditable. |
| `ManageToolCatalog` | `Control Panel` | `ToolRegistryService` | Manage tool catalog metadata. | `admin_id`, `operation`, tool metadata | changed tool summary | `ok`, `denied`, `invalid`, `not_found`, `failed` | `admin.tool_catalog_changed` | Tool metadata must not include secret namespaces or keys. |
| `ManageApprovalConfig` | `Control Panel` | `ApprovalService` | Manage approval workflows and surface configuration. | `admin_id`, `operation`, approval config | changed config summary | `ok`, `denied`, `invalid`, `not_found`, `failed` | `admin.approval_config_changed` | Surface credentials are referenced, not embedded. |
| `ManageRuntimeInstance` | `Control Panel` | `ToolRuntimeService` | Start, stop, inspect, or configure runtime instances. | `admin_id`, `operation`, tool/runtime target | runtime status summary | `ok`, `accepted`, `denied`, `invalid`, `not_found`, `unavailable`, `failed` | `admin.runtime_changed` | Runtime actions do not bypass policy for client requests. |
| `ManageSecretNamespace` | `Control Panel` | `SecretsManagementService` | Manage namespaces, profile/tool bindings, and component credentials. | `admin_id`, `operation`, namespace/binding/credential refs | changed secret metadata summary | `ok`, `denied`, `invalid`, `not_found`, `failed` | `admin.secret_namespace_changed` | Raw secret values must not be returned except through explicit secret-entry workflows. |
| `QueryAuditEvents` | `Control Panel` | `EventLoggingService` | Read audit history. | `admin_id`, filters, pagination intent | event summaries | `ok`, `denied`, `invalid`, `unavailable`, `failed` | `admin.audit_queried` | Query responses must preserve redaction rules. |

## Event Logging

### `AppendAuditEvent`

| Item | Contract |
|---|---|
| Sender | Domain components |
| Receiver | `EventLoggingService` |
| Purpose | Append an immutable event describing a state change, decision, or failure. |
| Request fields | `component`, `event_type`, `request_id`, optional `actor_context`, `outcome`, redacted `details`, `correlation_id` |
| Response fields | `audit_event_id`, `accepted_at` |
| Outcomes | `ok`, `accepted`, `invalid`, `unavailable`, `failed` |
| Audit events | `event_logging.event_appended`, `event_logging.event_rejected` |
| Security notes | Event logging receives redacted details and must not become a side channel for raw secrets. |

### `PersistAuditEvent`

| Item | Contract |
|---|---|
| Sender | `EventLoggingService` |
| Receiver | Audit event store |
| Purpose | Persist accepted audit events for query, retention, and export. |
| Request fields | `audit_event_id`, `event_body`, `retention_class`, optional `export_hints` |
| Response fields | `persisted`, optional `storage_ref`, optional `error` |
| Outcomes | `ok`, `accepted`, `invalid`, `unavailable`, `failed` |
| Audit events | `event_logging.event_persisted`, `event_logging.event_persist_failed` |
| Security notes | Persistence must preserve immutability and redaction. |

## Acceptance Checklist

- `BrokerGateway` only has contracts with `ClientProfileService` and `RequestService`.
- The only direct `SecretsManagementService` contracts are listed in
  [Secrets Access Rules](#secrets-access-rules).
- Tool registry contracts contain metadata only and no secret fields.
- Approval surface messages clearly cross an external trust boundary.
- Workload secret materialization and component credential handling are separate contracts.
- State-changing messages list audit events.
- No contract requires routes, ports, SQL tables, protobuf files, queue names, or deployment topology.

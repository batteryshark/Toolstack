# Project Nerve Center

This is the restart point for the Toolstack rebuild.

## Mission

Build an agentic tool management system slowly, one component at a time, with
ultra-simple code, clear ownership boundaries, and transport-neutral contracts.

The system should be understandable to a new reader without knowing the old
implementation or any previous design attempts.

## Current Shape

- Components are defined in [docs/component-decomposition.md](docs/component-decomposition.md).
- Component consume/produce boundaries are defined in [docs/component-io-contracts.md](docs/component-io-contracts.md).
- Message-level contracts are defined in [docs/message-contracts.md](docs/message-contracts.md).
- Clean-code expectations are summarized in [docs/coding-standards.md](docs/coding-standards.md).
- Work history lives in [docs/work-log.md](docs/work-log.md).
- Component-by-component build order lives in [docs/component-plans.md](docs/component-plans.md).

## Working Rules

- Build one component at a time.
- Prefer boring, explicit code over clever abstractions.
- Keep public surfaces small.
- Keep tests focused on behavior and boundaries.
- Do not choose REST, queues, databases, sandboxing, mTLS, or deployment shape until a component actually needs that decision.
- Do not let `BrokerGateway`, `RequestService`, or `ToolRegistryService` talk directly to `SecretsManagementService`.
- Do not let `ToolRegistryService` know secret namespaces, secret keys, or secret requirements.

## Current Status

The whole-system proof scaffold was intentionally removed because it bundled
too many components together. The repo is now in a pre-implementation planning
state, ready to build one component at a time.

There is no active test suite until the first isolated component is created.

## Suggested Next Step

Start with `ClientProfileService`.

Reason: it is small, central, and needed before meaningful request handling,
policy evaluation, or admin flows. Build it as a clean standalone component
with in-memory storage first, then decide whether persistence is needed.

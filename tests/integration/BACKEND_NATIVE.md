# Authenticated backend → native HTTP proof

From the repository root, using the existing offline admin Python environment:

```sh
PYTHONPATH=. python tests/integration/backend_native_wire.py
```

Requires the installed Xcode toolchain and existing FastAPI/uvicorn/cryptography dependencies.
This is separate from the MacNod fixture in README.md. It compiles all current
`macapp/Sources/ToolstackKit/*.swift` directly, with Foundation and a private module
cache, then invokes the actual ApiClient against real ephemeral loopback uvicorn
and broker servers. No response JSON is mocked and no file transport is used.

Fake credentials, manifests, SQLite, HOME and XDG state live in resolved temporary
scratch. Only the admin startup reconciler is patched; SPS is skipped. No tool
processes are started. Each native invocation has a 15-second timeout, compilation
120 seconds, startup/join five seconds. Server threads, sockets and stores are
closed in finally blocks; scratch is removed. Run in a disposable process because
the script intentionally changes its environment.

Checks: anonymous listTools receives 401; real login; zero-operation same-snapshot
membership; verified empty/B snapshots exclude cached ID A; missing receipt,
malformed manifest, stale receipt and old live listener return unknown; external
removal decodes deleted=false and retains files while unregistering the source;
managed removal decodes deleted=true and removes the directory. Catalog malformed
source is requested directly because listTools correctly rejects that source.

This is a backend/native client seam proof, not an AppKit, Keychain, Nod or UI run.

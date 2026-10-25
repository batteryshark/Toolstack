# Toolstack: native macOS operator app

A first-class native SwiftUI app for the operator surface (no webview), talking to the admin's
**JSON operator API** (`admin/api.py`) over loopback or a tailnet. Full web parity is
not proved. The approved Clear desk design is implemented and built. Strict canonical
decoders separate nullable health, liveness and recorded run intent. Failed loads
gate saves; rejected/unknown saves retain drafts, with three-way preservation and
comparison before retry. Mutations are scoped, stale responses are suppressed and
effects are never automatically replayed. Secret provisioning is host-side only;
obsolete value-provisioning UI is removed and the old API returns 410.

## Layout

- **`ToolstackKit`**, the testable core (Foundation only, no SwiftUI): `ApiClient` (an actor),
  a Keychain `TokenStore`, and the Codable response models. Headless-tested with `swift test`
  (a stubbed `URLProtocol`, no real admin).
- **`ToolstackApp`**, the SwiftUI app: a menu-bar extra + the main window (login → a broker
  control bar, Tools, Callers/policy, Secrets, Activity/audit, and Config).
- **`ToolstackKitTests`**: the API-client tests.

## Run it

Needs Xcode 26.5 / Swift 6.3.

```bash
cd macapp
swift test                 # run the API-client tests (headless)
swift run ToolstackApp      # launch the app, or:
open Package.swift          # open in Xcode, then Run the "ToolstackApp" scheme
```

Point it at a running admin (start one with `python3 -m admin serve`, or the one-box / desktop
shell). Default `http://127.0.0.1:8780`; override with `TOOLSTACK_ADMIN_URL`. The signed login
is remembered across launches in the Keychain.

For later LOCAL development only, see [packaging](packaging/README.md): existing
Apple Development identity, offline signing, and separate strict/deep verification.
A release build and separate local signature verification are recorded below;
do not use the historical notary script.

## Verification split (important)

The parent recorded 69 passing native tests at `b0a175`, integrated as `162ca5f`,
and an actual unsigned release build (14.74 seconds), then signing with an existing
approved Apple Development identity and a separate strict/deep verification PASS.
The app identifier is `com.toolstack.operator`. Native source is unchanged by the
integrated web source `54ce947`. This proves local signature consistency only.

Offscreen renders and fake-service tests do not establish trusted keyboard/Escape,
VoiceOver, native focus, window Close, named/default Cancel or comprehensive hit-target
acceptance. Those live checks, real backend/native wire verification and live Keychain
proof remain open. No activation, installation, notarization, Gatekeeper assessment
or distribution acceptance is claimed.

## Features

Implemented feature areas, not a verified parity/acceptance claim:

- **Broker**: start / stop / restart + health.
- **Tools**: add from a local folder or GitHub, author a manifest in-app (api / mcp),
  edit description + secret declarations, per-tool start/stop/restart, and
  update a tool from its source.
- **Callers**: create, issue / rotate / revoke tokens, enable tools, and edit policy
  per operation.
- **Activity**: a pane over the request + audit log; plus the active secret-backend view.

Catalog membership, separate add/start/register stages, ownership-sensitive removal
and caller header hints follow the [shared operator contracts](../admin/README.md#catalog-removal-and-authoring).
Policy adapters preserve advanced/unavailable grants without changing the broker's
full-replacement semantics. Unknown removal metadata leaves filesystem outcome unknown.

Login uses Keychain. No signed/notarized distribution readiness is claimed.
Same-account Mac development is not secret isolation; see
[security contracts and pending gates](../docs/security-contracts.md).

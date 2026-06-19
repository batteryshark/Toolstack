# Toolstack — native macOS operator app

A first-class native SwiftUI app for the operator surface (no webview), talking to the admin's
**JSON operator API** (`admin/api.py`) over loopback or a tailnet. It does everything the web
panel does, natively: sign in, run/stop the broker, manage callers/tokens/policies, author and
edit tools, set secret values, and watch requests + the audit log.

## Layout

- **`ToolstackKit`** — the testable core (Foundation only, no SwiftUI): `ApiClient` (an actor),
  a Keychain `TokenStore`, and the Codable response models. Headless-tested with `swift test`
  (a stubbed `URLProtocol`, no real admin).
- **`ToolstackApp`** — the SwiftUI app: a menu-bar extra + the main window (login → a broker
  control bar, Tools, Callers/policy, Secrets, Activity/audit, and Config).
- **`ToolstackKitTests`** — the API-client tests.

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

For a distributable build, `packaging/build-app.sh` produces the `.app` (icon included) and
`packaging/sign-and-notarize.sh` signs + notarizes it with a Developer ID (credentials live in
a gitignored `secrets/`).

## Verification split (important)

`ToolstackKit` is verified by `swift test` (requests, bearer auth, error mapping, snake_case
decoding). The **SwiftUI views are not** — there's no way to see a window in the build
environment, so the look/feel is confirmed by running it in Xcode.

## Features

The full operator surface over the admin API:

- **Broker** — start / stop / restart + health.
- **Tools** — add from a local folder or GitHub, author a manifest in-app (api / mcp / rest),
  edit description + secret declarations, set secret values, per-tool start/stop/restart, and
  update a tool from its source.
- **Callers** — create, issue / rotate / revoke tokens, enable tools, and edit policy
  (including rest per-`(verb, path)` rules).
- **Activity** — a pane over the request + audit log; plus the active secret-backend view.

The login persists in the Keychain, and the app ships as a signed, notarized `.app`.

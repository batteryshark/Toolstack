# Toolstack — native macOS operator app

A first-class native SwiftUI app for the operator surface (no webview), talking to the admin's
**JSON operator API** ([T-029], `admin/api.py`) over loopback. This is **phase 2** ([T-030]) of the
native track: the typed API client + the core screens. The rest of the UI + a signed `.app` is
[T-031].

## Layout

- **`ToolstackKit`** — the testable core (Foundation only, no SwiftUI): `ApiClient` (an actor) +
  the Codable models. Headless-tested with `swift test` (a stubbed `URLProtocol`, no real admin).
- **`ToolstackApp`** — the SwiftUI window: login → broker control + status → callers list/add.
- **`ToolstackKitTests`** — the API-client tests.

## Run it

Needs Xcode 26.5 / Swift 6.3 (present on this machine).

```bash
cd macapp
swift test                 # run the API-client tests (headless)
swift run ToolstackApp      # launch the app, or:
open Package.swift          # open in Xcode, then Run the "ToolstackApp" scheme
```

Point it at a running admin (start one with `python3 -m admin serve`, or the one-box / desktop
shell). Default `http://127.0.0.1:8780`; override with `TOOLSTACK_ADMIN_URL`. Sign in with the
admin password, then Start the broker and add callers — same operations as the web panel, native.

## Verification split (important)

`ToolstackKit` is verified by `swift test` (requests, bearer auth, error mapping, snake_case
decoding). The **SwiftUI views are not** — there's no way to see a window in the build
environment, so **the look/feel is confirmed by running it in Xcode**. If something's off in the
UI, that feedback drives the next iteration; the client logic underneath is covered by tests.

## Scope

- **Done ([T-030])**: API client (login, broker, callers) + tests; login / broker / callers screens.
- **Next ([T-031])**: policy editor, tokens (issue/rotate/revoke), tool authoring, secrets, audit;
  Keychain token persistence (today the token is held for the session only); a code-signed +
  notarized `.app` (Developer ID present). The `Revoke` button is stubbed (disabled) until then.

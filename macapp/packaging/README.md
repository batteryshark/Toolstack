# Packaging the Toolstack operator app

Turns the SwiftPM executable into a distributable, signed, notarized macOS `.app`.

## 1. Build the bundle (no credentials needed)

```sh
./packaging/build-app.sh        # → build/ToolstackApp.app (unsigned)
open build/ToolstackApp.app     # run it
```

`build-app.sh` does `swift build -c release`, then assembles `ToolstackApp.app/Contents/`
(`MacOS/ToolstackApp` + `Info.plist`). Because it's a real bundle, the app activates as a normal
windowed app — the `AppDelegate` activation-policy shim only mattered for `swift run`.

## 2. Sign + notarize (one command)

Notarization uses an **App Store Connect API key** — no Apple ID or app-specific password, so it
can't trip the account lock that `notarytool store-credentials` password auth sometimes does.

Two gitignored files supply the config (both already set up on this Mac):

- **`packaging/signing.env`** — `DEVELOPER_ID_APP` (the "Developer ID Application: …" identity) + `TEAM_ID`.
- **`secrets/secrets.env`** — `APP_STORE_CONNECT_API_ISSUER_ID` + `APP_STORE_CONNECT_API_KEY_PATH`
  (path to your `AuthKey_<KEYID>.p8`; the key-id is read from that filename).

Create the key once at **App Store Connect → Users and Access → Integrations → App Store Connect
API**, download the `.p8` into `macapp/secrets/`, and put its issuer id + path in `secrets/secrets.env`.

Then, every release — one command (builds, signs, notarizes, staples):

```sh
./packaging/sign-and-notarize.sh
```

It signs with Hardened Runtime + a secure timestamp, submits with the API key, waits, staples the
ticket, and finally zips the **stapled** bundle to `build/ToolstackApp.zip` — that zip is the
deliverable (the ticket travels inside the `.app`, so it passes Gatekeeper offline; the recipient
unzips and drags it to `/Applications`). `spctl --assess` at the end should report **accepted /
Notarized Developer ID** — i.e. it opens on any Mac with no Gatekeeper warning.

### Entitlements

None are needed for this app: it isn't sandboxed (Developer ID, not App Store), and under Hardened
Runtime both outgoing network connections (to the admin) and access to the app's **own** Keychain
items (the saved bearer token) are allowed without an entitlement. Add
`--entitlements packaging/Toolstack.entitlements` to the `codesign` line only if a future feature
needs a specific Hardened-Runtime exception (e.g. JIT).

## 3. Distribute

`build/ToolstackApp.zip` (produced in step 2) is the artifact — hand it out as-is. If you'd
rather ship a disk image instead of a zip, wrap the stapled app in a signed `.dmg`:

```sh
hdiutil create -volname "Toolstack" -srcfolder build/ToolstackApp.app \
    -ov -format UDZO build/Toolstack.dmg
codesign --sign "$DEVELOPER_ID_APP" build/Toolstack.dmg   # sign the dmg too if you ship it
```

## Versioning

Bump `CFBundleShortVersionString` (marketing, e.g. `0.2.0`) and `CFBundleVersion` (build number) in
`packaging/Info.plist` per release. The bundle id `com.toolstack.operator` matches the Keychain
service the app uses to remember your login — keep them in sync.

## Icons

- **App icon** — generated at build time (`sips` + `iconutil`) from `packaging/AppIcon-source.png`
  (a 1024×1024 PNG). Replace that file and rebuild to rebrand; no `.icns` is committed.
- **Menu-bar (systray) glyph** — `Sources/ToolstackApp/Resources/MenuBarIcon.png`, a 36×36
  *template* image (alpha = the glyph, RGB ignored) so macOS tints it for the light/dark menu bar.
  It's a SwiftPM resource loaded via `Bundle.module`; `build-app.sh` copies the resource bundle into
  the `.app` so it resolves there too.

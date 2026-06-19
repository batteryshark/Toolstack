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

## 2. Sign + notarize (needs your Developer ID)

One-time: store your Apple credentials for `notarytool` in the login keychain:

```sh
xcrun notarytool store-credentials toolstack-notary \
    --apple-id "you@example.com" --team-id "TEAMID" --password "APP_SPECIFIC_PASSWORD"
```

(Create the app-specific password at appleid.apple.com → Sign-In and Security.)

Find your signing identity:

```sh
security find-identity -v -p codesigning      # look for "Developer ID Application: …"
```

Then:

```sh
DEVELOPER_ID_APP="Developer ID Application: Your Name (TEAMID)" \
NOTARY_PROFILE="toolstack-notary" \
./packaging/sign-and-notarize.sh
```

This signs with Hardened Runtime + a secure timestamp, submits to Apple, waits for the result,
and staples the ticket. `spctl --assess` at the end should report **accepted / Notarized Developer
ID** — i.e. it opens on any Mac with no Gatekeeper warning.

### Entitlements

None are needed for this app: it isn't sandboxed (Developer ID, not App Store), and under Hardened
Runtime both outgoing network connections (to the admin) and access to the app's **own** Keychain
items (the saved bearer token) are allowed without an entitlement. Add
`--entitlements packaging/Toolstack.entitlements` to the `codesign` line only if a future feature
needs a specific Hardened-Runtime exception (e.g. JIT).

## 3. (optional) Wrap in a .dmg

```sh
hdiutil create -volname "Toolstack" -srcfolder build/ToolstackApp.app \
    -ov -format UDZO build/Toolstack.dmg
```

Sign the dmg too if you distribute it: `codesign --sign "$DEVELOPER_ID_APP" build/Toolstack.dmg`.

## Versioning

Bump `CFBundleShortVersionString` (marketing, e.g. `0.2.0`) and `CFBundleVersion` (build number) in
`packaging/Info.plist` per release. The bundle id `com.toolstack.operator` matches the Keychain
service the app uses to remember your login — keep them in sync.

## Icon

Drop an `AppIcon.icns` into `packaging/`, uncomment the two marked lines in `build-app.sh` and
`Info.plist`, and rebuild.

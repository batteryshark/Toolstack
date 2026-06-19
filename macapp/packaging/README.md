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

Config lives in **`packaging/signing.env`** (gitignored) — already filled in with this Mac's
Developer ID identity, team id `Y734633UDM`, and the notary profile name `toolstack-notary`.
Nothing in that file is a secret.

**One-time, run by you** — registers your Apple credential in the login keychain:

```sh
./packaging/notarize-setup.sh
```

It reads your Apple ID / team / profile from `signing.env` and lets `notarytool` prompt you for the
**app-specific password** (hidden input — never on the command line, in shell history, or in this
repo). Create that password at appleid.apple.com → Sign-In and Security → App-Specific Passwords,
signed in as the **same Apple ID** as `APPLE_ID` in `signing.env` (it must be a member of the team —
a mismatch is the usual cause of a `401` here).

Then, every release — one command (builds, signs, notarizes, staples):

```sh
./packaging/sign-and-notarize.sh
```

It signs with Hardened Runtime + a secure timestamp, submits to Apple, waits, and staples the
ticket. `spctl --assess` at the end should report **accepted / Notarized Developer ID** — i.e. it
opens on any Mac with no Gatekeeper warning.

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

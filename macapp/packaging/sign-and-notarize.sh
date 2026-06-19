#!/bin/bash
# Build → code-sign (Hardened Runtime) → notarize → staple build/ToolstackApp.app for distribution
# outside the App Store. Config (identity / team id / notary profile) is read from the gitignored
# packaging/signing.env, so this is one command:
#
#   ./packaging/sign-and-notarize.sh
#
# ONE-TIME, run by YOU (it needs your Apple ID + an app-specific password — not stored in the repo):
#   xcrun notarytool store-credentials toolstack-notary \
#       --apple-id "<your-apple-id>" --team-id "Y734633UDM" --password "<app-specific-password>"
# (Create the app-specific password at appleid.apple.com → Sign-In and Security.)
set -euo pipefail
cd "$(dirname "$0")/.."

# Local, gitignored signing config (identity / team id / notary profile). Env vars still override.
[ -f packaging/signing.env ] && . packaging/signing.env

APP="build/ToolstackApp.app"
ZIP="build/ToolstackApp.zip"
: "${DEVELOPER_ID_APP:?set it in packaging/signing.env (or the env) to your 'Developer ID Application: …' identity}"
: "${NOTARY_PROFILE:?set it in packaging/signing.env (or the env) to your notarytool keychain profile}"

echo "› building a fresh bundle"
./packaging/build-app.sh >/dev/null

echo "› signing (Hardened Runtime, secure timestamp)"
# No sandbox (Developer ID, not App Store). Hardened Runtime needs no entitlements here: outgoing
# network and the app's own Keychain items are allowed. Add an entitlements file only if you hit a
# specific restriction (e.g. --entitlements packaging/Toolstack.entitlements).
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APP" "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "› notarizing (zip → submit → wait)"
rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait

echo "› stapling the ticket"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=4 "$APP"   # Gatekeeper should say: accepted, Notarized Developer ID

echo "✓ signed + notarized: $APP"
echo "  distribute it, or wrap it in a .dmg (see packaging/README.md)."

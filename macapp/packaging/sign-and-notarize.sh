#!/bin/bash
# Code-sign (Hardened Runtime), notarize, and staple build/ToolstackApp.app for distribution
# outside the App Store. Run ./packaging/build-app.sh first.
#
# One-time setup (stores your Apple ID + app-specific password in the login keychain):
#   xcrun notarytool store-credentials toolstack-notary \
#       --apple-id "you@example.com" --team-id "TEAMID" --password "app-specific-password"
#
# Then:
#   DEVELOPER_ID_APP="Developer ID Application: Your Name (TEAMID)" \
#   NOTARY_PROFILE="toolstack-notary" \
#   ./packaging/sign-and-notarize.sh
#
# Find your identity with:  security find-identity -v -p codesigning
set -euo pipefail
cd "$(dirname "$0")/.."

APP="build/ToolstackApp.app"
ZIP="build/ToolstackApp.zip"
: "${DEVELOPER_ID_APP:?set DEVELOPER_ID_APP to your 'Developer ID Application: Name (TEAMID)' identity}"
: "${NOTARY_PROFILE:?set NOTARY_PROFILE to the notarytool keychain profile you created (see header)}"
[ -d "$APP" ] || { echo "error: $APP not found — run ./packaging/build-app.sh first" >&2; exit 1; }

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

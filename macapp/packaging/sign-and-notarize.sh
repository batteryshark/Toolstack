#!/bin/bash
# Build → code-sign (Hardened Runtime) → notarize → staple build/ToolstackApp.app for distribution
# outside the App Store. One command, no account/password step:
#
#   ./packaging/sign-and-notarize.sh
#
# Reads two gitignored files:
#   packaging/signing.env  — DEVELOPER_ID_APP (the "Developer ID Application: …" identity)
#   secrets/secrets.env    — APP_STORE_CONNECT_API_ISSUER_ID + APP_STORE_CONNECT_API_KEY_PATH
#                            (.p8 path; the key-id is read from the AuthKey_<KEYID>.p8 filename)
# The App Store Connect API key notarizes WITHOUT an Apple ID / app-specific password, so it can't
# trip the account lock that password auth does.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f packaging/signing.env ] && . packaging/signing.env
[ -f secrets/secrets.env ] && . secrets/secrets.env

APP="build/ToolstackApp.app"
SUBMIT_ZIP="build/ToolstackApp-submit.zip"   # what notarytool ingests (pre-staple)
ZIP="build/ToolstackApp.zip"                 # the distributable (the STAPLED .app, zipped)
: "${DEVELOPER_ID_APP:?set it in packaging/signing.env to your 'Developer ID Application: …' identity}"
: "${APP_STORE_CONNECT_API_ISSUER_ID:?set it in secrets/secrets.env (App Store Connect API issuer id)}"
: "${APP_STORE_CONNECT_API_KEY_PATH:?set it in secrets/secrets.env (path to your AuthKey_*.p8)}"
[ -f "$APP_STORE_CONNECT_API_KEY_PATH" ] || { echo "error: API key not found at $APP_STORE_CONNECT_API_KEY_PATH" >&2; exit 1; }
# key-id is the AuthKey_<KEYID>.p8 filename stem
KEY_ID="$(basename "$APP_STORE_CONNECT_API_KEY_PATH" | sed -E 's/^AuthKey_([A-Za-z0-9]+)\.p8$/\1/')"
[ "$KEY_ID" != "$(basename "$APP_STORE_CONNECT_API_KEY_PATH")" ] || { echo "error: key must be named AuthKey_<KEYID>.p8" >&2; exit 1; }

echo "› building a fresh bundle"
./packaging/build-app.sh >/dev/null

echo "› signing (Hardened Runtime, secure timestamp)"
# No sandbox (Developer ID, not App Store). Hardened Runtime needs no entitlements here: outgoing
# network and the app's own Keychain items are allowed. Add an entitlements file only if you hit a
# specific restriction (e.g. --entitlements packaging/Toolstack.entitlements).
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APP" "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "› notarizing via App Store Connect API key (key-id $KEY_ID)"
rm -f "$SUBMIT_ZIP"
ditto -c -k --keepParent "$APP" "$SUBMIT_ZIP"
xcrun notarytool submit "$SUBMIT_ZIP" \
    --key "$APP_STORE_CONNECT_API_KEY_PATH" \
    --key-id "$KEY_ID" \
    --issuer "$APP_STORE_CONNECT_API_ISSUER_ID" \
    --wait
rm -f "$SUBMIT_ZIP"

echo "› stapling the ticket"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=4 "$APP"   # Gatekeeper should say: accepted, Notarized Developer ID

echo "› zipping the stapled app for distribution"
# Zip the STAPLED bundle so Gatekeeper accepts it offline (the ticket travels in the .app, not
# the notarization service). ditto --keepParent preserves the .app wrapper + symlinks/perms.
rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"

echo "✓ signed + notarized + stapled: $APP"
echo "  distribute: $ZIP — a signed, notarized .app zipped up (unzip → drag to /Applications)."

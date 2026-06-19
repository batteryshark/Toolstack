#!/bin/bash
# One-time: register your Apple credentials with notarytool so signing can notarize. Reads the
# Apple ID / team / profile from the gitignored packaging/signing.env. You type the app-specific
# password at notarytool's OWN prompt — it's never passed on the command line, saved to shell
# history, or stored in this repo.
#
#   ./packaging/notarize-setup.sh
#
# Get an app-specific password at appleid.apple.com → Sign-In and Security → App-Specific Passwords,
# signed in as the SAME Apple ID as APPLE_ID below (it must be a member of the team).
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f packaging/signing.env ] && . packaging/signing.env
: "${APPLE_ID:?set APPLE_ID in packaging/signing.env to your Apple Developer account email}"
: "${TEAM_ID:?set TEAM_ID in packaging/signing.env}"
: "${NOTARY_PROFILE:?set NOTARY_PROFILE in packaging/signing.env}"

echo "Registering notarytool profile '$NOTARY_PROFILE' for $APPLE_ID (team $TEAM_ID)."
echo "You'll be prompted for your app-specific password (hidden; not stored by this script)."
# No --password: notarytool prompts for it interactively and validates against Apple before storing.
xcrun notarytool store-credentials "$NOTARY_PROFILE" --apple-id "$APPLE_ID" --team-id "$TEAM_ID"
echo "✓ stored. Now run: ./packaging/sign-and-notarize.sh"

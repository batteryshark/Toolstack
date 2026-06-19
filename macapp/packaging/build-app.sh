#!/bin/bash
# Build ToolstackApp.app — a proper .app bundle from the SwiftPM release binary, so the operator
# app is a double-clickable, signable, first-class macOS app (not just `swift run`).
#
#   ./packaging/build-app.sh            # -> build/ToolstackApp.app (unsigned)
#
# Then sign + notarize with ./packaging/sign-and-notarize.sh (needs your Developer ID).
set -euo pipefail
cd "$(dirname "$0")/.."

APP_NAME="ToolstackApp"
OUT="build/${APP_NAME}.app"
CONTENTS="${OUT}/Contents"

echo "› swift build -c release"
swift build -c release
BIN="$(swift build -c release --show-bin-path)/${APP_NAME}"
[ -x "$BIN" ] || { echo "error: built binary not found at $BIN" >&2; exit 1; }

echo "› assembling ${OUT}"
rm -rf "$OUT"
mkdir -p "${CONTENTS}/MacOS" "${CONTENTS}/Resources"
cp "$BIN" "${CONTENTS}/MacOS/${APP_NAME}"
cp packaging/Info.plist "${CONTENTS}/Info.plist"
# Drop an AppIcon.icns into packaging/ and uncomment to brand the app:
# cp packaging/AppIcon.icns "${CONTENTS}/Resources/AppIcon.icns"
#   (also add  <key>CFBundleIconFile</key><string>AppIcon</string>  to Info.plist)

# Fail fast if the Info.plist is malformed.
plutil -lint "${CONTENTS}/Info.plist" >/dev/null

echo "✓ built ${OUT}"
echo "  unsigned — run it with:  open \"${OUT}\""
echo "  ship it with:            ./packaging/sign-and-notarize.sh"

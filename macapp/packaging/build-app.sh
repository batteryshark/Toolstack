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
BINDIR="$(swift build -c release --show-bin-path)"
BIN="$BINDIR/${APP_NAME}"
[ -x "$BIN" ] || { echo "error: built binary not found at $BIN" >&2; exit 1; }

echo "› assembling ${OUT}"
rm -rf "$OUT"
mkdir -p "${CONTENTS}/MacOS" "${CONTENTS}/Resources"
cp "$BIN" "${CONTENTS}/MacOS/${APP_NAME}"
cp packaging/Info.plist "${CONTENTS}/Info.plist"

# App icon: generate AppIcon.icns from the source logo (Info.plist points at CFBundleIconFile=AppIcon).
ICONSET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
    sips -z "$s" "$s" packaging/AppIcon-source.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z "$((s*2))" "$((s*2))" packaging/AppIcon-source.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "${CONTENTS}/Resources/AppIcon.icns"
rm -rf "$(dirname "$ICONSET")"

# SwiftPM resource bundle(s) — so Bundle.module (the menu-bar icon) resolves in the packaged app.
for b in "$BINDIR"/*.bundle; do [ -e "$b" ] && cp -R "$b" "${CONTENTS}/Resources/"; done

# Fail fast if the Info.plist is malformed.
plutil -lint "${CONTENTS}/Info.plist" >/dev/null

echo "✓ built ${OUT}"
echo "  unsigned — run it with:  open \"${OUT}\""
echo "  ship it with:            ./packaging/sign-and-notarize.sh"

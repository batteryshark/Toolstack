#!/bin/bash
# Independent signature check only: no signing or Gatekeeper assessment.
set -euo pipefail
APP="$(cd "$(dirname "$0")/.." && pwd)/build/Toolstack Operator.app"
if [ "$#" -gt 1 ]; then echo "Usage: $0 [/path/to/existing.app]" >&2; exit 2; fi
if [ "$#" -eq 1 ]; then APP="$1"; fi
case "$APP" in *.app) ;; *) echo 'error: expected an existing .app directory' >&2; exit 2 ;; esac
[ -d "$APP/Contents" ] || { echo 'error: app bundle missing' >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$APP"

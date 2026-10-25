#!/bin/bash
# LOCAL development only. Never builds, sources credentials or notarizes.
set -euo pipefail
IDENTITY="${TOOLSTACK_LOCAL_SIGN_IDENTITY:-}"
APP="$(cd "$(dirname "$0")/.." && pwd)/build/Toolstack Operator.app"
usage() { echo "Usage: $0 [--identity 'Apple Development: ...'] [--app /path/to/existing.app]"; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --identity|--app)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            if [ "$1" = --identity ]; then IDENTITY="$2"; else APP="$2"; fi
            shift 2 ;;
        --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$IDENTITY" in
    'Apple Development: '?*) ;;
    *) echo 'error: explicit existing Apple Development identity required' >&2; exit 2 ;;
esac
case "$APP" in *.app) ;; *) echo 'error: expected an existing .app directory' >&2; exit 2 ;; esac
[ -d "$APP/Contents" ] || { echo 'error: app bundle missing' >&2; exit 1; }
codesign --force --sign "$IDENTITY" --timestamp=none "$APP"
echo 'LOCAL signing finished; run verify-local.sh separately before use.'
